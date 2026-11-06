"""Production ledger mask filtering, invalid-arm preservation and dump stop."""
from pathlib import Path
import os,shlex,subprocess,tempfile
root=Path(__file__).resolve().parents[3]
with tempfile.TemporaryDirectory() as d:
 p=Path(d);(p/'zephyr/sys').mkdir(parents=True)
 (p/'zephyr/kernel.h').write_text('#include <stddef.h>\n#define ARRAY_SIZE(a) (sizeof(a)/sizeof(*(a)))\nstatic unsigned irq_lock(void){return 0;}\nstatic void irq_unlock(unsigned k){(void)k;}\nstatic void k_msleep(unsigned n){(void)n;}\n')
 (p/'zephyr/sys/printk.h').write_text('#define printk(...) ((void)0)\n')
 (p/'test.c').write_text('#include <assert.h>\n#include "'+str(root/'src/frame_ledger.c')+'"\n'+'''
int main(void){
 ledger_command_mask((1<<3)|(1<<9));
 for(unsigned c=0;c<16;c++)ledger_note(1,42,c,LEDGER_SOURCE,0,0,0);
 assert(count==2 && records[0].child==3 && records[1].child==9);
 ledger_command_mask(15);assert(count==2 && ledger_child_enabled(9));
 ledger_command_mask(0x800f);assert(count==2);
 ledger_command(-1);ledger_note(1,43,3,LEDGER_SOURCE,0,0,0);assert(count==2);
 ledger_command(3);assert(count==0 && ledger_child_enabled(3) && !ledger_child_enabled(9));
 ledger_command_mask((1<<3)|(1<<6)|(1<<9));assert(count==0);
 for(unsigned c=0;c<16;c++)ledger_note(1,44,c,LEDGER_SOURCE,0,0,0);
 assert(count==3);
 ledger_command_mask((1U<<11)|(1U<<15));
 for(unsigned c=0;c<=16;c++) ledger_note(1,45,c,LEDGER_SOURCE,0,0,0);
 assert(count==2 && ledger_child_enabled(11) && ledger_child_enabled(15) && !ledger_child_enabled(16));
 ledger_command(16);assert(count==2);
}
''')
 subprocess.run(shlex.split(os.environ.get('CC','cc'))+['-DCONFIG_RELAY_FRAME_LEDGER=1','-std=c11','-Wall','-Wextra','-Wno-unused-variable','-Werror','-I'+str(p),str(p/'test.c'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True)
print('Ledger mask: 2/3-child filtering, invalid-arm preservation, single-child compatibility and dump stop passed')
