# obcert

Доверяй корневому сертификату Минцифры РФ только для нужных доменов.

obcert создаёт локальный доверенный корень с ограничением по доменам
(`nameConstraints`) и кросс-подписывает им корень Минцифры. Реальные сертификаты
Минцифры принимаются только для доменов из вашего списка (и их поддоменов).

## Важно про браузеры
- **Firefox** — ограничение соблюдается строго.
- **Safari / Chrome** — ограничение соблюдается ненадёжно; сертификат Минцифры может
  быть принят и для других доменов. Приложение честно предупреждает об этом.

## Сборка
```bash
swift test                      # ядро (CheburcertCore)
brew install nss xcodegen
./scripts/bundle-certutil.sh
cd App/CheburcertApp && xcodegen generate
xcodebuild -scheme obcert -configuration Release build
```

## Как это работает
См. `docs/superpowers/specs/2026-08-27-cheburcert-design.md`.

## Ручная проверка
См. `docs/manual-verification.md`.
