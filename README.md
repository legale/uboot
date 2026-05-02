# uboot-mediatek for openwrt

Этот репозиторий содержит пакет `uboot-mediatek` для openwrt и новые фичи в
uboot, в первую очередь `nvmem-cells` и `l2sh`.

## Подключение в openwrt

Ниже минимальная последовательность, чтобы подключить этот репозиторий как
локальный feed и заменить core-пакет `uboot-mediatek`:

```sh
git clone https://github.com/openwrt/openwrt
git clone https://github.com/legale/uboot.git
cd openwrt
cp feeds.conf.default feeds.conf
printf '\nsrc-link uboot %s\n' "$(cd ../uboot/openwrt && pwd)" >> feeds.conf
./scripts/feeds update -a
./scripts/feeds install -a
./scripts/feeds install -f -p uboot uboot-mediatek
```

## Какие `CONFIG_` включать

### `nvmem-cells`

Для поддержки `nvmem-cells` в uboot нужна опция:

```config
CONFIG_NVMEM=y
```

Отдельной `CONFIG_` именно для `nvmem-cells` нет. Само использование задаётся в
DTS через свойства `nvmem-cells` и `nvmem-cell-names`.

В этом репозитории `CONFIG_NVMEM=y` уже включён как минимум в:

- `mt7621_yuncore_ax820_defconfig`
- `mt7981_yuncore_ax835_nor_defconfig`
- `mt7981_yuncore_fap830_nor_defconfig`

### `l2sh`

Для транспорта `l2sh` в uboot нужна опция:

```config
CONFIG_L2SH=y
```

На практических конфигурациях из этого репозитория вместе с ней уже включены
нужные сетевые опции, в том числе `CONFIG_MEDIATEK_ETH=y`.

Если нужен клиент `l2sh` внутри целевой системы openwrt, включите пакет:

```config
CONFIG_PACKAGE_l2sh=y
```

Во время работы uboot транспорт управляется переменной окружения `l2sh=1`.

### Host compile `l2sh` клиента

Для standalone host-сборки клиента `l2sh` openwrt `.config` не нужен. Сборка
делается отдельно:

```sh
make -C openwrt/uboot-mediatek/l2sh-client-host-build
```

Готовый host-бинарник появится здесь:

```text
openwrt/uboot-mediatek/l2sh-client-host-build/l2sh
```

По умолчанию используется `musl-gcc`. При необходимости можно передать свой
компилятор:

```sh
make -C openwrt/uboot-mediatek/l2sh-client-host-build CC=/path/to/musl-gcc
```

## Выбор варианта uboot в `.config`

В openwrt надо выбрать один вариант `u-boot-*` под свою плату.

Для `ax820`:

```config
CONFIG_PACKAGE_u-boot-mt7621_yuncore_ax820=y
```

Для `ax835`:

```config
CONFIG_PACKAGE_u-boot-mt7981_yuncore_ax835-nor=y
```

Для `fap830`:

```config
CONFIG_PACKAGE_u-boot-mt7981_yuncore_fap830-nor=y
```

Если нужен target-пакет клиента `l2sh`, добавьте:

```config
CONFIG_PACKAGE_l2sh=y
```

## Сборка и артефакты

Сборка пакета:

```sh
make package/feeds/uboot/uboot-mediatek/compile -j"$(nproc)" V=s
```

Примеры, где искать готовые файлы:

- `ax820`: `bin/targets/ramips/mt7621/`
- `ax835`: `bin/targets/mediatek/filogic/`
- `fap830`: `bin/targets/mediatek/filogic/`

Основные артефакты:

- `ax820`: `mt7621_yuncore_ax820-u-boot-mt7621.bin`
- `ax835`: `mt7981_yuncore_ax835-nor-u-boot.fip`
- `fap830`: `mt7981_yuncore_fap830-nor-u-boot.fip`

Для `ax820` дополнительно публикуются:

- `mt7621_yuncore_ax820-u-boot.bin`
- `mt7621_yuncore_ax820-u-boot-spl-ddr.img`
- `mt7621_yuncore_ax820-u-boot-lzma.img`

Если отдельно собирается пакет `uboot-tools`, его пакеты появятся в каталоге:

```text
bin/packages/*/*/base/
```
