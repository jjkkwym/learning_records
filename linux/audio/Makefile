all:
	gcc -o player player.c -lasound
	gcc -o recorder recorder.c -lasound
arm:
	arm-openwrt-linux-gcc -o player_arm player.c -L /home/flc/nccd_proj/v3.5.1/out/r328s3-std_xr829/compile_dir/target/alsa-lib-1.1.4.1/src/.libs/ -lasound
	arm-openwrt-linux-gcc -o recorder_arm recorder.c -L /home/flc/nccd_proj/v3.5.1/out/r328s3-std_xr829/compile_dir/target/alsa-lib-1.1.4.1/src/.libs/ -lasound