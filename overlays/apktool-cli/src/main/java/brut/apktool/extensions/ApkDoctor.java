/*
 * Local Apktool CLI extension.
 *
 * Scope:
 * - static diagnostics,
 * - checksum manifest before decode,
 * - conservative APK ZIP/resource repair for malformed magic headers.
 *
 * Out of scope:
 * - bypassing runtime integrity checks,
 * - bypassing signatures, paid features, DRM or license checks,
 * - rewriting application logic in DEX/smali.
 */
package brut.apktool.extensions;

import brut.androlib.exceptions.AndrolibException;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

public final class ApkDoctor {
    private static final int DEX_METHOD_INDEX_LIMIT = 65536;
    private static final int COPY_BUFFER_SIZE = 128 * 1024;
    private static final byte[] BAD_9638 = new byte[]{(byte) 0x96, 0x38};
    private static final byte[] BINARY_XML_MAGIC = new byte[]{0x03, 0x00, 0x08, 0x00};
    private static final byte[] ARSC_MAGIC = new byte[]{0x02, 0x00, 0x0c, 0x00};
    private static final byte[] GZIP_MAGIC = new byte[]{0x1f, (byte) 0x8b};
    private static final String OKHTTP_PUBLIC_SUFFIX = "okhttp3/internal/publicsuffix/publicsuffixes.gz";

    private ApkDoctor() {
    }

    public static void run(String[] args) throws AndrolibException {
        boolean json = false;
        boolean fix = false;
        File output = null;
        List<String> positional = new ArrayList<>();

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if ("--json".equals(arg)) {
                json = true;
            } else if ("--fix".equals(arg) || "--repair".equals(arg)) {
                fix = true;
            } else if ("--output".equals(arg) || "-o".equals(arg)) {
                if (i + 1 >= args.length) {
                    throw new AndrolibException("Missing value for " + arg);
                }
                output = new File(args[++i]);
            } else if ("--help".equals(arg) || "-h".equals(arg)) {
                printUsage();
                return;
            } else {
                positional.add(arg);
            }
        }

        if (positional.size() != 1) {
            printUsage();
            throw new AndrolibException("Expected exactly one APK path.");
        }

        File apk = new File(positional.get(0));
        DoctorResult result;
        if (fix) {
            File repairOutput = output != null ? output : defaultRepairOutput(apk);
            result = repair(apk, repairOutput, null, true);
        } else {
            result = inspect(apk);
        }

        if (json) {
            printJson(result);
        } else {
            printText(result);
        }

        if (hasSeverity(result.findings, Severity.ERROR)) {
            System.exit(2);
        }
    }

    /**
     * Called from patched cmdDecode before ApkDecoder is created.
     * It never touches the original APK. If a repairable APK anomaly is detected, a repaired sidecar APK is produced and
     * the decoder receives that repaired copy. Original entry hashes are written before any APK bytes are transformed.
     */
    public static File preDecode(File apk, File outDir) throws AndrolibException {
        File manifestFile = checksumSidecarForDecode(apk, outDir);
        try {
            ChecksumManifest manifest = writeChecksumManifest(apk, manifestFile);
            System.out.println("I: Original APK checksums written to " + manifest.outputFile.getPath());
        } catch (IOException ex) {
            throw new AndrolibException("Cannot write original APK checksum manifest: " + ex.getMessage(), ex);
        }

        DoctorResult inspection = inspect(apk);
        boolean shouldRepair = false;
        for (Finding finding : inspection.findings) {
            if (finding.repairable) {
                shouldRepair = true;
                break;
            }
        }

        if (!shouldRepair) {
            return apk;
        }

        File repairedApk = repairedSidecarForDecode(apk, outDir);
        DoctorResult repaired = repair(apk, repairedApk, manifestFile, false);
        if (!repaired.repaired) {
            return apk;
        }

        System.out.println("I: Repairable APK anomalies detected; decoding repaired sidecar " + repaired.outputApk.getPath());
        for (Finding finding : repaired.findings) {
            if (finding.action != null) {
                System.out.println("I: " + finding.action);
            }
        }
        return repaired.outputApk;
    }

    private static void printUsage() {
        System.out.println("apktool doctor|x-doctor [--json] [--fix|--repair] [-o fixed.apk] <apk>");
        System.out.println("Static APK diagnostics plus conservative ZIP/resource magic repair.");
    }

    private static DoctorResult inspect(File apk) {
        List<Finding> findings = new ArrayList<>();
        DoctorResult result = new DoctorResult(apk, null, false, findings);

        if (!apk.isFile()) {
            findings.add(new Finding(Severity.ERROR, "INPUT", "APK path does not exist or is not a regular file: " + apk));
            return result;
        }
        if (!apk.getName().toLowerCase(Locale.ROOT).endsWith(".apk")) {
            findings.add(new Finding(Severity.WARN, "INPUT", "Input file does not use .apk extension."));
        }

        try (ZipFile zip = new ZipFile(apk)) {
            inspectZipEntries(zip, findings);
            inspectKnownPayloads(zip, findings);
        } catch (ZipException ex) {
            findings.add(new Finding(Severity.ERROR, "ZIP", "Invalid ZIP/APK container: " + ex.getMessage()));
        } catch (IOException ex) {
            findings.add(new Finding(Severity.ERROR, "IO", "Cannot read APK: " + ex.getMessage()));
        }

        return result;
    }

    private static DoctorResult repair(File apk, File outputApk, File checksumManifest, boolean writeChecksumWhenMissing) throws AndrolibException {
        if (!apk.isFile()) {
            throw new AndrolibException("APK path does not exist or is not a regular file: " + apk);
        }

        try {
            if (checksumManifest == null && writeChecksumWhenMissing) {
                checksumManifest = defaultChecksumOutput(apk);
            }
            if (checksumManifest != null && !checksumManifest.isFile()) {
                ChecksumManifest manifest = writeChecksumManifest(apk, checksumManifest);
                System.out.println("I: Original APK checksums written to " + manifest.outputFile.getPath());
            }

            File parent = outputApk.getAbsoluteFile().getParentFile();
            if (parent != null) {
                Files.createDirectories(parent.toPath());
            }

            List<Finding> findings = new ArrayList<>();
            boolean repaired = rewriteApkWithRepairs(apk, outputApk, findings);
            if (!repaired) {
                findings.add(new Finding(Severity.INFO, "REPAIR", "No repairable magic/header anomalies were found."));
            }
            DoctorResult result = new DoctorResult(apk, outputApk, repaired, findings);
            appendPostRepairDiagnostics(outputApk, result);
            return result;
        } catch (IOException ex) {
            throw new AndrolibException("APK repair failed: " + ex.getMessage(), ex);
        }
    }

    private static void appendPostRepairDiagnostics(File outputApk, DoctorResult result) {
        if (outputApk == null || !outputApk.isFile()) {
            return;
        }
        DoctorResult inspection = inspect(outputApk);
        for (Finding finding : inspection.findings) {
            result.findings.add(finding);
        }
    }

    private static boolean rewriteApkWithRepairs(File apk, File outputApk, List<Finding> findings) throws IOException {
        boolean repaired = false;
        try (ZipFile zip = new ZipFile(apk);
             ZipOutputStream out = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(outputApk)))) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                byte[] data = readAll(zip, entry);
                RepairDecision decision = repairEntry(entry.getName(), data);
                byte[] outputData = data;
                if (decision != null) {
                    repaired = true;
                    outputData = decision.data;
                    findings.add(new Finding(
                            Severity.WARN,
                            decision.code,
                            entry.getName() + ": " + decision.message,
                            true,
                            "repaired " + entry.getName() + " -> " + decision.message));
                }
                writeZipEntry(out, entry, outputData);
            }
        }

        if (!repaired) {
            Files.deleteIfExists(outputApk.toPath());
        }
        return repaired;
    }

    private static RepairDecision repairEntry(String name, byte[] data) {
        if (data.length == 0) {
            return null;
        }

        if ("AndroidManifest.xml".equals(name) && startsWith(data, BAD_9638)) {
            return replacePrefix(data, BINARY_XML_MAGIC, "MAGIC_9638_XML", "replaced suspicious 96 38 prefix with binary XML magic 03 00 08 00");
        }
        if (isBinaryXmlResource(name) && startsWith(data, BAD_9638)) {
            return replacePrefix(data, BINARY_XML_MAGIC, "MAGIC_9638_XML", "replaced suspicious 96 38 prefix with binary XML magic 03 00 08 00");
        }
        if ("resources.arsc".equals(name) && startsWith(data, BAD_9638)) {
            return replacePrefix(data, ARSC_MAGIC, "MAGIC_9638_ARSC", "replaced suspicious 96 38 prefix with resources.arsc magic 02 00 0c 00");
        }
        if (OKHTTP_PUBLIC_SUFFIX.equals(name) && startsWith(data, BAD_9638)) {
            return replacePrefix(data, GZIP_MAGIC, "OKHTTP3_PUBLIC_SUFFIX_GZIP", "replaced suspicious 96 38 prefix with gzip magic 1f 8b for okhttp3 public suffix database");
        }
        if (OKHTTP_PUBLIC_SUFFIX.equals(name) && data.length >= 2 && !startsWith(data, GZIP_MAGIC)) {
            return null;
        }
        return null;
    }

    private static boolean isBinaryXmlResource(String name) {
        return name.startsWith("res/") && name.endsWith(".xml");
    }

    private static RepairDecision replacePrefix(byte[] original, byte[] replacementPrefix, String code, String message) {
        if (original.length < replacementPrefix.length) {
            return null;
        }
        byte[] patched = original.clone();
        System.arraycopy(replacementPrefix, 0, patched, 0, replacementPrefix.length);
        return new RepairDecision(code, message, patched);
    }

    private static void writeZipEntry(ZipOutputStream out, ZipEntry originalEntry, byte[] data) throws IOException {
        ZipEntry clone = new ZipEntry(originalEntry.getName());
        clone.setComment(originalEntry.getComment());
        clone.setExtra(originalEntry.getExtra());
        clone.setTime(originalEntry.getTime());

        if (originalEntry.getMethod() == ZipEntry.STORED) {
            CRC32 crc = new CRC32();
            crc.update(data);
            clone.setMethod(ZipEntry.STORED);
            clone.setSize(data.length);
            clone.setCompressedSize(data.length);
            clone.setCrc(crc.getValue());
        } else {
            clone.setMethod(ZipEntry.DEFLATED);
        }

        out.putNextEntry(clone);
        out.write(data);
        out.closeEntry();
    }

    private static void inspectZipEntries(ZipFile zip, List<Finding> findings) {
        Map<String, String> caseFolded = new HashMap<>();
        int entryCount = 0;
        boolean hasManifest = false;
        boolean hasArsc = false;
        boolean hasDex = false;
        boolean hasOkHttp3 = false;

        Enumeration<? extends ZipEntry> entries = zip.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            entryCount++;
            String name = entry.getName();

            if ("AndroidManifest.xml".equals(name)) {
                hasManifest = true;
            } else if ("resources.arsc".equals(name)) {
                hasArsc = true;
            } else if (name.matches("classes(\\d*)\\.dex")) {
                hasDex = true;
            }
            if (name.startsWith("okhttp3/") || name.contains("/okhttp3/")) {
                hasOkHttp3 = true;
            }

            if (name.startsWith("/") || name.startsWith("\\\\") || name.contains("../") || name.contains("..\\\\")) {
                findings.add(new Finding(Severity.ERROR, "ZIP_ENTRY", "Path traversal or absolute entry name: " + name));
            }
            if (name.indexOf('\0') >= 0) {
                findings.add(new Finding(Severity.ERROR, "ZIP_ENTRY", "NUL byte in entry name: " + printable(name)));
            }
            if (name.contains("\\\\")) {
                findings.add(new Finding(Severity.WARN, "ZIP_ENTRY", "Backslash in ZIP entry name may be non-portable: " + name));
            }
            if (name.length() > 240) {
                findings.add(new Finding(Severity.WARN, "ZIP_ENTRY", "Very long entry name may break Windows tooling: " + name.length() + " chars: " + name));
            }
            if (name.startsWith(".") || name.contains("/.")) {
                findings.add(new Finding(Severity.INFO, "ZIP_ENTRY", "Hidden-style entry name: " + name));
            }

            String lower = name.toLowerCase(Locale.ROOT);
            String previous = caseFolded.put(lower, name);
            if (previous != null && !previous.equals(name)) {
                findings.add(new Finding(Severity.WARN, "ZIP_ENTRY", "Case-insensitive name collision: " + previous + " <-> " + name));
            }
        }

        findings.add(new Finding(Severity.INFO, "ZIP", "Entry count: " + entryCount));
        if (!hasManifest) {
            findings.add(new Finding(Severity.ERROR, "APK", "AndroidManifest.xml is missing."));
        }
        if (!hasArsc) {
            findings.add(new Finding(Severity.INFO, "APK", "resources.arsc is missing; this may be valid for resource-less APKs."));
        }
        if (!hasDex) {
            findings.add(new Finding(Severity.WARN, "APK", "No classes*.dex found."));
        }
        if (hasOkHttp3) {
            findings.add(new Finding(Severity.INFO, "OKHTTP3", "okhttp3 package/resource entries detected."));
        }
    }

    private static void inspectKnownPayloads(ZipFile zip, List<Finding> findings) throws IOException {
        ZipEntry manifest = zip.getEntry("AndroidManifest.xml");
        if (manifest != null) {
            byte[] head = readPrefix(zip, manifest, 16);
            if (startsWith(head, BINARY_XML_MAGIC)) {
                findings.add(new Finding(Severity.INFO, "MANIFEST", "AndroidManifest.xml uses binary XML magic."));
            } else if (startsWith(head, BAD_9638)) {
                findings.add(new Finding(Severity.WARN, "MAGIC_9638_XML", "AndroidManifest.xml starts with suspicious 96 38 prefix and is repairable as binary XML magic.", true, null));
            } else {
                findings.add(new Finding(Severity.WARN, "MANIFEST", "AndroidManifest.xml does not look like standard binary XML."));
            }
        }

        ZipEntry arsc = zip.getEntry("resources.arsc");
        if (arsc != null) {
            byte[] head = readPrefix(zip, arsc, 16);
            if (startsWith(head, ARSC_MAGIC)) {
                long declaredSize = uint32le(head, 4);
                long compressedSize = arsc.getSize();
                findings.add(new Finding(Severity.INFO, "ARSC", "resources.arsc header OK, declared chunk size=" + declaredSize + ", zip size=" + compressedSize));
                if (compressedSize > 0 && declaredSize > compressedSize) {
                    findings.add(new Finding(Severity.WARN, "ARSC", "resources.arsc declares size larger than ZIP entry size."));
                }
            } else if (startsWith(head, BAD_9638)) {
                findings.add(new Finding(Severity.WARN, "MAGIC_9638_ARSC", "resources.arsc starts with suspicious 96 38 prefix and is repairable as RES_TABLE_TYPE magic.", true, null));
            } else {
                findings.add(new Finding(Severity.ERROR, "ARSC", "resources.arsc does not start with RES_TABLE_TYPE header."));
            }
        }

        ZipEntry okHttpSuffix = zip.getEntry(OKHTTP_PUBLIC_SUFFIX);
        if (okHttpSuffix != null) {
            byte[] head = readPrefix(zip, okHttpSuffix, 8);
            if (startsWith(head, GZIP_MAGIC)) {
                findings.add(new Finding(Severity.INFO, "OKHTTP3", OKHTTP_PUBLIC_SUFFIX + " gzip magic OK."));
            } else if (startsWith(head, BAD_9638)) {
                findings.add(new Finding(Severity.WARN, "OKHTTP3_PUBLIC_SUFFIX_GZIP", OKHTTP_PUBLIC_SUFFIX + " starts with suspicious 96 38 prefix and is repairable as gzip magic.", true, null));
            } else {
                findings.add(new Finding(Severity.WARN, "OKHTTP3", OKHTTP_PUBLIC_SUFFIX + " does not start with gzip magic."));
            }
        }

        List<? extends ZipEntry> dexEntries = sortedDexEntries(zip);
        for (ZipEntry dex : dexEntries) {
            inspectDex(zip, dex, findings);
            inspectDexForOkHttp3(zip, dex, findings);
        }

        inspectResourceXmlMagic(zip, findings);
    }

    private static void inspectResourceXmlMagic(ZipFile zip, List<Finding> findings) throws IOException {
        Enumeration<? extends ZipEntry> entries = zip.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            String name = entry.getName();
            if (!isBinaryXmlResource(name)) {
                continue;
            }
            byte[] head = readPrefix(zip, entry, 4);
            if (startsWith(head, BAD_9638)) {
                findings.add(new Finding(Severity.WARN, "MAGIC_9638_XML", name + " starts with suspicious 96 38 prefix and is repairable as binary XML magic.", true, null));
            }
        }
    }

    private static List<? extends ZipEntry> sortedDexEntries(ZipFile zip) {
        List<ZipEntry> dexEntries = new ArrayList<>();
        Enumeration<? extends ZipEntry> entries = zip.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            if (entry.getName().matches("classes(\\d*)\\.dex")) {
                dexEntries.add(entry);
            }
        }
        Collections.sort(dexEntries, Comparator.comparing(ZipEntry::getName));
        return dexEntries;
    }

    private static void inspectDex(ZipFile zip, ZipEntry dex, List<Finding> findings) throws IOException {
        byte[] head = readPrefix(zip, dex, 112);
        if (head.length < 112 || !startsWith(head, new byte[]{'d', 'e', 'x', '\n'})) {
            findings.add(new Finding(Severity.ERROR, "DEX", dex.getName() + " has invalid or truncated DEX header."));
            return;
        }

        long fileSize = uint32le(head, 0x20);
        long headerSize = uint32le(head, 0x24);
        long stringIds = uint32le(head, 0x38);
        long typeIds = uint32le(head, 0x40);
        long protoIds = uint32le(head, 0x48);
        long fieldIds = uint32le(head, 0x50);
        long methodIds = uint32le(head, 0x58);

        findings.add(new Finding(
                Severity.INFO,
                "DEX",
                dex.getName() + " file_size=" + fileSize
                        + ", header_size=" + headerSize
                        + ", strings=" + stringIds
                        + ", types=" + typeIds
                        + ", protos=" + protoIds
                        + ", fields=" + fieldIds
                        + ", methods=" + methodIds));

        if (methodIds >= DEX_METHOD_INDEX_LIMIT) {
            findings.add(new Finding(Severity.WARN, "DEX_LIMIT", dex.getName()
                    + " method_ids_size=" + methodIds
                    + " reaches/exceeds 65536; injectors must split into multidex instead of adding to this dex."));
        }
        if (fieldIds >= DEX_METHOD_INDEX_LIMIT || typeIds >= DEX_METHOD_INDEX_LIMIT || protoIds >= DEX_METHOD_INDEX_LIMIT) {
            findings.add(new Finding(Severity.WARN, "DEX_LIMIT", dex.getName()
                    + " has a 16-bit index table near/exceeding 65536; bytecode changes may overflow indexes."));
        }
        if (headerSize != 112) {
            findings.add(new Finding(Severity.WARN, "DEX", dex.getName() + " has unexpected header_size=" + headerSize));
        }
        if (dex.getSize() > 0 && fileSize != dex.getSize()) {
            findings.add(new Finding(Severity.WARN, "DEX", dex.getName()
                    + " header file_size does not match ZIP entry size: " + fileSize + " != " + dex.getSize()));
        }
    }

    private static void inspectDexForOkHttp3(ZipFile zip, ZipEntry dex, List<Finding> findings) throws IOException {
        byte[] data = readAll(zip, dex);
        if (indexOf(data, "Lokhttp3/".getBytes(StandardCharsets.US_ASCII)) >= 0
                || indexOf(data, "okhttp3/".getBytes(StandardCharsets.US_ASCII)) >= 0) {
            findings.add(new Finding(Severity.INFO, "OKHTTP3", dex.getName() + " references okhttp3."));
        }
    }

    private static ChecksumManifest writeChecksumManifest(File apk, File outputFile) throws IOException {
        File parent = outputFile.getAbsoluteFile().getParentFile();
        if (parent != null) {
            Files.createDirectories(parent.toPath());
        }

        List<EntryChecksum> entries = new ArrayList<>();
        try (ZipFile zip = new ZipFile(apk)) {
            Enumeration<? extends ZipEntry> enumeration = zip.entries();
            while (enumeration.hasMoreElements()) {
                ZipEntry entry = enumeration.nextElement();
                entries.add(hashEntry(zip, entry));
            }
        }
        Collections.sort(entries, Comparator.comparing(e -> e.name));

        String apkSha256 = sha256File(apk);
        StringBuilder out = new StringBuilder(8192);
        out.append("{\n");
        out.append("  \"schema\": \"apktool-rebase-lab.checksums.v1\",\n");
        out.append("  \"createdUtc\": \"").append(jsonEscape(utcNow())).append("\",\n");
        out.append("  \"apk\": \"").append(jsonEscape(apk.getPath())).append("\",\n");
        out.append("  \"apkSha256\": \"").append(apkSha256).append("\",\n");
        out.append("  \"entries\": [\n");
        for (int i = 0; i < entries.size(); i++) {
            EntryChecksum e = entries.get(i);
            out.append("    {\"name\": \"").append(jsonEscape(e.name)).append("\", ")
                    .append("\"size\": ").append(e.size).append(", ")
                    .append("\"compressedSize\": ").append(e.compressedSize).append(", ")
                    .append("\"crc32\": \"").append(e.crc32).append("\", ")
                    .append("\"sha256\": \"").append(e.sha256).append("\"}");
            if (i + 1 < entries.size()) {
                out.append(',');
            }
            out.append('\n');
        }
        out.append("  ]\n");
        out.append("}\n");

        Files.write(outputFile.toPath(), out.toString().getBytes(StandardCharsets.UTF_8));
        return new ChecksumManifest(outputFile, apkSha256, entries.size());
    }

    private static EntryChecksum hashEntry(ZipFile zip, ZipEntry entry) throws IOException {
        MessageDigest digest = sha256Digest();
        byte[] buffer = new byte[COPY_BUFFER_SIZE];
        try (InputStream input = zip.getInputStream(entry); DigestInputStream digestInput = new DigestInputStream(input, digest)) {
            while (digestInput.read(buffer) >= 0) {
                // DigestInputStream updates the digest.
            }
        }
        return new EntryChecksum(
                entry.getName(),
                entry.getSize(),
                entry.getCompressedSize(),
                String.format(Locale.ROOT, "%08x", entry.getCrc()),
                hex(digest.digest()));
    }

    private static String sha256File(File file) throws IOException {
        MessageDigest digest = sha256Digest();
        byte[] buffer = new byte[COPY_BUFFER_SIZE];
        try (InputStream input = new BufferedInputStream(new FileInputStream(file)); DigestInputStream digestInput = new DigestInputStream(input, digest)) {
            while (digestInput.read(buffer) >= 0) {
                // DigestInputStream updates the digest.
            }
        }
        return hex(digest.digest());
    }

    private static MessageDigest sha256Digest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is not available", ex);
        }
    }

    private static byte[] readPrefix(ZipFile zip, ZipEntry entry, int limit) throws IOException {
        try (InputStream input = zip.getInputStream(entry)) {
            ByteArrayOutputStream output = new ByteArrayOutputStream(Math.min(limit, 4096));
            byte[] buffer = new byte[512];
            int remaining = limit;
            while (remaining > 0) {
                int read = input.read(buffer, 0, Math.min(buffer.length, remaining));
                if (read < 0) {
                    break;
                }
                output.write(buffer, 0, read);
                remaining -= read;
            }
            return output.toByteArray();
        }
    }

    private static byte[] readAll(ZipFile zip, ZipEntry entry) throws IOException {
        try (InputStream input = zip.getInputStream(entry)) {
            ByteArrayOutputStream output = new ByteArrayOutputStream(Math.max(32, Math.min((int) Math.max(0, entry.getSize()), COPY_BUFFER_SIZE)));
            copy(input, output);
            return output.toByteArray();
        }
    }

    private static void copy(InputStream input, OutputStream output) throws IOException {
        byte[] buffer = new byte[COPY_BUFFER_SIZE];
        int read;
        while ((read = input.read(buffer)) >= 0) {
            output.write(buffer, 0, read);
        }
    }

    private static boolean startsWith(byte[] data, byte[] prefix) {
        if (data.length < prefix.length) {
            return false;
        }
        for (int i = 0; i < prefix.length; i++) {
            if (data[i] != prefix[i]) {
                return false;
            }
        }
        return true;
    }

    private static int indexOf(byte[] data, byte[] needle) {
        if (needle.length == 0 || data.length < needle.length) {
            return -1;
        }
        for (int i = 0; i <= data.length - needle.length; i++) {
            int j = 0;
            while (j < needle.length && data[i + j] == needle[j]) {
                j++;
            }
            if (j == needle.length) {
                return i;
            }
        }
        return -1;
    }

    private static long uint32le(byte[] data, int offset) {
        if (offset + 4 > data.length) {
            return -1L;
        }
        return ((long) data[offset] & 0xff)
                | (((long) data[offset + 1] & 0xff) << 8)
                | (((long) data[offset + 2] & 0xff) << 16)
                | (((long) data[offset + 3] & 0xff) << 24);
    }

    private static boolean hasSeverity(List<Finding> findings, Severity severity) {
        for (Finding finding : findings) {
            if (finding.severity == severity) {
                return true;
            }
        }
        return false;
    }

    private static File checksumSidecarForDecode(File apk, File outDir) {
        return new File(outDir.getPath() + ".original-checksums.json");
    }

    private static File repairedSidecarForDecode(File apk, File outDir) {
        File parent = outDir.getAbsoluteFile().getParentFile();
        String base = outDir.getName();
        File sidecar = new File(parent == null ? new File(".") : parent, base + ".repaired-input.apk");
        if (apk.getAbsoluteFile().equals(sidecar.getAbsoluteFile())) {
            return new File(parent == null ? new File(".") : parent, base + ".repaired-input.2.apk");
        }
        return sidecar;
    }

    private static File defaultRepairOutput(File apk) {
        String path = apk.getPath();
        if (path.toLowerCase(Locale.ROOT).endsWith(".apk")) {
            return new File(path.substring(0, path.length() - 4) + ".repaired.apk");
        }
        return new File(path + ".repaired.apk");
    }

    private static File defaultChecksumOutput(File apk) {
        return new File(apk.getPath() + ".original-checksums.json");
    }

    private static void printText(DoctorResult result) {
        System.out.println("APK Doctor: " + result.inputApk.getPath());
        if (result.outputApk != null) {
            System.out.println("Output APK: " + result.outputApk.getPath());
            System.out.println("Repaired: " + result.repaired);
        }
        for (Finding finding : result.findings) {
            System.out.println("[" + finding.severity + "] " + finding.code + " - " + finding.message);
        }
    }

    private static void printJson(DoctorResult result) {
        StringBuilder out = new StringBuilder();
        out.append("{\n");
        out.append("  \"apk\": \"").append(jsonEscape(result.inputApk.getPath())).append("\",\n");
        out.append("  \"outputApk\": ");
        if (result.outputApk == null) {
            out.append("null");
        } else {
            out.append("\"").append(jsonEscape(result.outputApk.getPath())).append("\"");
        }
        out.append(",\n");
        out.append("  \"repaired\": ").append(result.repaired).append(",\n");
        out.append("  \"findings\": [\n");
        for (int i = 0; i < result.findings.size(); i++) {
            Finding finding = result.findings.get(i);
            out.append("    {\"severity\": \"").append(finding.severity).append("\", ")
                    .append("\"code\": \"").append(jsonEscape(finding.code)).append("\", ")
                    .append("\"repairable\": ").append(finding.repairable).append(", ")
                    .append("\"message\": \"").append(jsonEscape(finding.message)).append("\"");
            if (finding.action != null) {
                out.append(", \"action\": \"").append(jsonEscape(finding.action)).append("\"");
            }
            out.append("}");
            if (i + 1 < result.findings.size()) {
                out.append(',');
            }
            out.append('\n');
        }
        out.append("  ]\n");
        out.append("}\n");
        System.out.print(out.toString());
    }

    private static String printable(String value) {
        return value.replace("\0", "\\0");
    }

    private static String utcNow() {
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.ROOT);
        format.setTimeZone(TimeZone.getTimeZone("UTC"));
        return format.format(new Date());
    }

    private static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            out.append(String.format(Locale.ROOT, "%02x", value & 0xff));
        }
        return out.toString();
    }

    private static String jsonEscape(String value) {
        StringBuilder out = new StringBuilder(value.length() + 16);
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            switch (ch) {
                case '"':
                    out.append("\\\"");
                    break;
                case '\\':
                    out.append("\\\\");
                    break;
                case '\b':
                    out.append("\\b");
                    break;
                case '\f':
                    out.append("\\f");
                    break;
                case '\n':
                    out.append("\\n");
                    break;
                case '\r':
                    out.append("\\r");
                    break;
                case '\t':
                    out.append("\\t");
                    break;
                default:
                    if (ch < 0x20) {
                        out.append(String.format(Locale.ROOT, "\\u%04x", (int) ch));
                    } else {
                        out.append(ch);
                    }
                    break;
            }
        }
        return out.toString();
    }

    private enum Severity {
        INFO,
        WARN,
        ERROR
    }

    private static final class DoctorResult {
        private final File inputApk;
        private final File outputApk;
        private final boolean repaired;
        private final List<Finding> findings;

        private DoctorResult(File inputApk, File outputApk, boolean repaired, List<Finding> findings) {
            this.inputApk = inputApk;
            this.outputApk = outputApk;
            this.repaired = repaired;
            this.findings = findings;
        }
    }

    private static final class Finding {
        private final Severity severity;
        private final String code;
        private final String message;
        private final boolean repairable;
        private final String action;

        private Finding(Severity severity, String code, String message) {
            this(severity, code, message, false, null);
        }

        private Finding(Severity severity, String code, String message, boolean repairable, String action) {
            this.severity = severity;
            this.code = code;
            this.message = message;
            this.repairable = repairable;
            this.action = action;
        }
    }

    private static final class RepairDecision {
        private final String code;
        private final String message;
        private final byte[] data;

        private RepairDecision(String code, String message, byte[] data) {
            this.code = code;
            this.message = message;
            this.data = data;
        }
    }

    private static final class EntryChecksum {
        private final String name;
        private final long size;
        private final long compressedSize;
        private final String crc32;
        private final String sha256;

        private EntryChecksum(String name, long size, long compressedSize, String crc32, String sha256) {
            this.name = name;
            this.size = size;
            this.compressedSize = compressedSize;
            this.crc32 = crc32;
            this.sha256 = sha256;
        }
    }

    private static final class ChecksumManifest {
        private final File outputFile;
        private final String apkSha256;
        private final int entryCount;

        private ChecksumManifest(File outputFile, String apkSha256, int entryCount) {
            this.outputFile = outputFile;
            this.apkSha256 = apkSha256;
            this.entryCount = entryCount;
        }
    }
}
