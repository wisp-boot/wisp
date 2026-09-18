wisp-modules 1
builtin	builtin_thing
module	aes	kernel/crypto/aes.ko				crypto-aes
module	base	kernel/drivers/base.ko				
module	ext4	kernel/fs/ext4.ko	mid			fs-ext4 fs-ext3
module	helper	kernel/drivers/net/helper.ko				
module	mid	kernel/drivers/mid.ko	base	aes	helper	
module	netfs	kernel/fs/netfs.ko	helper			
module	tpm	kernel/drivers/char/tpm.ko				acpi*:MSFT0101:* of:N*T*Ctcg,tpm-tis-i2c
