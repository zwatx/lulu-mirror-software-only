# Sourced with the completed image mounted read-only at /inspect.
grep -qx 'service.adb.tcp.port=-1' /inspect/build.prop
grep -qx 'ro.mirror.software_only=1' /inspect/build.prop
# Launcher3 is a privileged Android system app in this product.
test -s /inspect/priv-app/Launcher3/Launcher3.apk
test -s /inspect/priv-app/Settings/Settings.apk
python /inputs/check-owner.py --system /inspect --public-key /owner.pub > /artifacts/owner-check.json
grep -a -q 'Mirror revival: sent adbd restart and framework startup requests' /inspect/bin/vold
test -s /inspect/framework/wifi-service.jar
test -s /inspect/lib/modules/pronto/pronto_wlan.ko
cmp /inspect/lib/modules/pronto/pronto_wlan.ko /artifacts/pronto_wlan.ko
test ! -e /inspect/lib/modules/mirror_camera_diag.ko
test ! -e /inspect/vendor/lib/libMD2.so
if grep -q 'mirror_camera_diag' /inspect/etc/init.qcom.post_boot.sh; then
  echo 'Diagnostic kernel module must not be loaded by the recovery baseline.' >&2
  exit 1
fi
if grep -q '^[^#].*Ext Spk Switch' /inspect/etc/mixer_paths_sbc.xml; then
  echo 'Speaker amplifier routing is included.'
else
  echo 'Missing Mirror speaker amplifier routing.' >&2
  exit 1
fi
