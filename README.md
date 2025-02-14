# spp-stuff

Collection of random stuff

## Debugging """Guide"""

 - Put machine into testsigning (`bcdedit /set testsigning on`)
 - Install drivers under `drivers/` by running `install.cmd` in each folder
 - Install `sppdebug.reg` to have SPPSvc auto-suspend on startup
 - Use PPLcontrol to set debugger to `PP Windows` protection level
 - Use [ScyllaHide](https://github.com/x64dbg/ScyllaHide/releases/tag/v1.4) with VMProtect profile for debugging
 - Take care to avoid having debugger attached at the end of a [heap execute](https://github.com/WitherOrNot/warbird-docs/blob/main/WarbirdModern.md#heap-executes), or sppsvc will crash with Fast Fail Exception

## Credits

asdcorp, abbodi, Lyssa - ImHex patterns
asdcorp - SPP debug setup, `tokens_rebuild_v2.py`
