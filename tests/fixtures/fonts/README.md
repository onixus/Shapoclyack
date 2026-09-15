# Font fixtures

`DejaVuSans.ttf` is a subset of DejaVu Sans 2.37 (Bitstream Vera licence plus
the DejaVu public-domain additions): ASCII, Latin-1, Cyrillic (U+0410–U+044F,
Ё/ё), «», №, dashes and the ellipsis. Regenerate from the upstream file with:

```
pyftsubset DejaVuSans.ttf \
  --unicodes="U+0020-007E,U+00A0-00FF,U+0401,U+0410-044F,U+0451,U+2013,U+2014,U+2026,U+00AB,U+00BB,U+2116" \
  --no-hinting --desubroutinize --output-file=tests/fixtures/fonts/DejaVuSans.ttf
```

It exists so the PDF renderer's Unicode path (`api/services/reports/render.py`)
is exercised on every host, not only on the images that install
`fonts-dejavu-core`. It is not shipped in any image.
