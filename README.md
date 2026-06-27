# apktool-rebase-lab

Nadbudowa nad upstream `iBotPeaches/Apktool`, utrzymywana jako overlay/rebase. Repo nie jest ciężkim forkiem: klonuje aktualny upstream, kopiuje lokalne klasy rozszerzeń i patchuje minimalnie `Main.java`.

## Zakres aktualnej wersji

- pobiera upstream Apktool z gałęzi `main`,
- dodaje komendę `doctor` / `x-doctor`,
- dodaje pre-hook przed `apktool d|decode`,
- zapisuje sumy kontrolne oryginalnego APK i wszystkich wpisów ZIP przed dekompilacją,
- jeżeli wykryje naprawialny uszkodzony magic header, tworzy sidecar APK i dekompiluje sidecar zamiast modyfikować oryginał,
- wykrywa `okhttp3` w zasobach i w DEX strings,
- naprawia `okhttp3/internal/publicsuffix/publicsuffixes.gz`, gdy zaczyna się od podejrzanego prefiksu `96 38` zamiast gzip magic `1f 8b`.

## Granica funkcjonalna

Implementacja nie obchodzi runtime anti-tamper, podpisów, płatnych funkcji, DRM, license checks ani logiki integralności aplikacji. Naprawa dotyczy tylko warstwy kontenera APK/ZIP i nagłówków zasobów, których nie trzeba interpretować jako modyfikacji logiki programu.

## Build lokalny

Linux/macOS/Git Bash:

```bash
./scripts/sync-upstream.sh
```

Windows PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\sync-upstream.ps1
```

Wynikowy JAR zwykle trafia do:

```text
work/Apktool/brut.apktool/apktool-cli/build/libs/apktool-cli-all.jar
```

## Użycie diagnostyki

```bash
java -jar apktool-cli-all.jar doctor app.apk
java -jar apktool-cli-all.jar doctor --json app.apk
```

## Użycie naprawy bez dekompilacji

```bash
java -jar apktool-cli-all.jar doctor --fix app.apk
java -jar apktool-cli-all.jar doctor --fix -o app.fixed.apk app.apk
```

`--fix` nigdy nie nadpisuje wejściowego APK. Jeżeli są naprawialne anomalie, tworzy `*.repaired.apk`. Jeżeli nie ma czego naprawiać, nie produkuje zbędnego APK.

## Automatyka przed dekompilacją

Po patchu normalne:

```bash
java -jar apktool-cli-all.jar d app.apk
```

robi preflight:

1. zapisuje manifest sum kontrolnych do:

```text
<outDir>.original-checksums.json
```

2. wykrywa naprawialne wpisy,
3. jeżeli trzeba, tworzy:

```text
<outDir>.repaired-input.apk
```

4. uruchamia właściwy `ApkDecoder` na oryginale albo na sidecarze.

Dla domyślnego `app.apk` i domyślnego outputu `app` powstaną np.:

```text
app.original-checksums.json
app.repaired-input.apk
app/
```

## Obsługiwane automatyczne naprawy

Aktualne reguły są celowo konserwatywne:

| Wejście | Warunek | Akcja |
|---|---:|---|
| `AndroidManifest.xml` | prefix `96 38` | zamiana początku na binary XML magic `03 00 08 00` |
| `res/**/*.xml` | prefix `96 38` | zamiana początku na binary XML magic `03 00 08 00` |
| `resources.arsc` | prefix `96 38` | zamiana początku na ARSC magic `02 00 0c 00` |
| `okhttp3/internal/publicsuffix/publicsuffixes.gz` | prefix `96 38` | zamiana początku na gzip magic `1f 8b` |

Dodatkowe przypadki należy dopisywać jako jawne reguły w `ApkDoctor.repairEntry()`. Nie ma globalnej naprawy „dowolnego `96 38`”, bo to generowałoby fałszywe pozytywy i korupcję binarek.

## Manifest sum kontrolnych

Manifest zawiera:

- SHA-256 całego APK,
- dla każdego wpisu ZIP/APK: nazwę, rozmiar, rozmiar skompresowany, CRC32 i SHA-256 nieskompresowanej zawartości.

Format:

```json
{
  "schema": "apktool-rebase-lab.checksums.v1",
  "createdUtc": "2026-06-27T00:00:00Z",
  "apk": "app.apk",
  "apkSha256": "...",
  "entries": [
    {"name": "AndroidManifest.xml", "size": 123, "compressedSize": 120, "crc32": "00000000", "sha256": "..."}
  ]
}
```

## 65536 / 0x10000

`65536` dziesiętnie to `0x10000`, nie `0x65536`. W DEX jest to limit indeksów 16-bitowych dla części tabel. Lokalny patch nie próbuje zwiększać tego limitu, bo poprawnym kierunkiem jest multidex albo ograniczenie zmian w danym `classes.dex`.
