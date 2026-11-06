"""Execute receiver settings persistence and budget application from esb.c."""
from pathlib import Path
import os, shlex, subprocess, sys, tempfile
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'harness'))
from c_extract import extract_block
source = (HERE.parents[2] / 'src/connection/esb.c').read_text()
a = source.index('static struct relay_runtime_settings relay_settings =')
b = source.index('struct tdma_publication {', a)
state = source[a:b]
def function(name):
    return extract_block(source, rf'^(?:static )?(?:void|int) {name}\([^;{{]*\)\s*\{{')
prefix = r'''
#define CONFIG_RELAY_RUNTIME_LAYOUT 1
#define CONFIG_RELAY_MAX_TRACKERS 16
#define CONFIG_RELAY_MAX_REPAIRS 1
#define CONFIG_RELAY_REPAIR_FLOOR 0
#define CONFIG_RELAY_SLOT_TICKS 16
#define CONFIG_RELAY_TPS_MIN 100
#define CONFIG_RELAY_TPS_MAX 120
#define IS_ENABLED(x) (x)
#define K_FOREVER 0
#define LOG_WRN(...) ((void)0)
#define RELAY_LAYOUT_SETTINGS 261
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "relay_protocol.h"
#include "relay_demand.h"
static unsigned mutex,depth,writes,recalculates,prints,wakes;
static struct relay_control relay_grants;
static uint8_t relay_profile;
static int tracker_store_lock,tdma_membership_wake,write_error,read_result=-ENOENT;
static uint8_t storage[10];
static unsigned irq_lock(void){assert(!depth);depth=1;return 0;}
static void irq_unlock(unsigned key){assert(!key && depth);depth=0;}
static void k_mutex_lock(int *p,int timeout){(void)p;(void)timeout;assert(!mutex);mutex=1;}
static void k_mutex_unlock(int *p){(void)p;assert(mutex);mutex=0;}
static void k_sem_give(int *p){(void)p;wakes++;}
static int printk(const char *format,...){(void)format;prints++;return 0;}
static int sys_read_checked(unsigned key,void *out,unsigned n){assert(key==261 && n==10);if(read_result==10 || read_result==9)memcpy(out,storage,read_result);return read_result;}
static int sys_write_checked(unsigned key,const void *data,unsigned n){assert(key==261 && n==10 && !depth && mutex);writes++;if(write_error)return write_error;memcpy(storage,data,n);return 0;}
static void tdma_recalculate(bool forced){assert(forced && mutex && !depth);recalculates++;}
'''
cases = r'''
static void defaults(void){
 relay_settings=(struct relay_runtime_settings){16,1,16,100,120,0};
 relay_applied_settings=relay_settings;relay_settings_generation=1;relay_applied_generation=0;
 writes=recalculates=prints=wakes=0;write_error=0;read_result=-ENOENT;
}
static void saved(unsigned trackers,unsigned repairs,unsigned width,unsigned floor,unsigned cap){
 storage[0]=2;storage[1]=trackers;storage[2]=repairs;storage[3]=width;
 relay_put_be16(storage+4,floor);relay_put_be16(storage+6,cap);storage[8]=0;storage[9]=relay_crc8(7,storage,9);read_result=10;
}
int main(void){
 defaults();relay_settings.repair_floor=1;
 assert(!esb_relay_layout_set("max_repairs",0));
 assert(relay_settings.repair_floor==0 && relay_settings.max_repairs==0);
 assert(!esb_relay_layout_set("max_repairs",5));
 assert(relay_settings.repair_floor==3 && relay_settings.max_repairs==3);
 assert(!esb_relay_layout_set("max_trackers",11));
 assert(!esb_relay_layout_set("max_repairs",5));
 assert(relay_settings.repair_floor==5);
 assert(!esb_relay_layout_set("repair_floor",1));
 assert(!esb_relay_layout_set("max_repairs",3));
 assert(relay_settings.repair_floor==1 && relay_settings.max_repairs==3);
 assert(!esb_relay_layout_set("max_repairs",0));
 assert(relay_settings.repair_floor==0);
 defaults();relay_settings_load();assert(relay_settings.max_trackers==16 && relay_settings.max_repairs==1);
 saved(11,5,16,100,120);storage[0]=1;storage[8]=relay_crc8(7,storage,8);read_result=9;relay_settings_load();assert(relay_settings.max_trackers==11 && relay_settings.max_repairs==5 && relay_settings.repair_floor==5);
 saved(11,5,16,100,120);relay_settings_load();assert(relay_settings.max_trackers==11 && relay_settings.max_repairs==5);
 defaults();saved(16,5,16,100,120);relay_settings_load();assert(relay_settings.max_repairs==3 && !writes);
 defaults();saved(16,1,14,100,120);relay_settings_load();assert(relay_settings.slot_ticks==16 && relay_settings.max_repairs==5);
 defaults();saved(11,5,16,100,120);storage[9]^=1;relay_settings_load();assert(relay_settings.max_trackers==16);
 defaults();saved(11,5,15,100,120);relay_settings_load();assert(relay_settings.slot_ticks==(CONFIG_RELAY_EXPERIMENTAL_SLOT_15?15:16));
 defaults();assert(!esb_relay_layout_set("max_repairs",5));
 assert(relay_settings.max_repairs==3 && storage[2]==3 && writes==1 && recalculates==1 && wakes==1);
 assert(relay_settings_generation==2 && relay_applied_generation==0);
 assert(!esb_relay_layout_set("max_repairs",5));assert(writes==1 && recalculates==1 && relay_settings_generation==2);
 assert(esb_relay_layout_set("tps_min",120)==-EINVAL);
 assert(esb_relay_layout_set("slot_ticks",14)==-EINVAL);
 assert(esb_relay_layout_set("max_trackers",0)==-EINVAL);
 assert(esb_relay_layout_set("max_trackers",256)==-EINVAL);
 assert(esb_relay_layout_set("unknown",1)==-EINVAL);
 assert(writes==1 && !mutex && !depth);
 write_error=-EIO;assert(esb_relay_layout_set("max_trackers",11)==-EIO);
 assert(relay_settings.max_trackers==16 && relay_settings_generation==2 && recalculates==1);
 write_error=0;assert(!esb_relay_layout_set("max_trackers",11));assert(!esb_relay_layout_set("max_repairs",5));
 assert(!esb_relay_layout_set("tps_min",120));assert(esb_relay_layout_set("tps_max",100)==-EINVAL);
 assert(!esb_relay_layout_set("tps_min",100));assert(!esb_relay_layout_set("tps_max",100));
 int result=esb_relay_layout_set("slot_ticks",15);
 assert(result==(CONFIG_RELAY_EXPERIMENTAL_SLOT_15?0:-EINVAL));
 defaults();assert(!esb_relay_layout_set("max_trackers",11));assert(!esb_relay_layout_set("max_repairs",5));
 assert(esb_relay_layout_set("repair_floor",6)==-EINVAL);assert(!esb_relay_layout_set("repair_floor",5));
 assert(relay_settings.repair_floor==5 && storage[8]==5);
 unsigned before=writes;assert(!esb_relay_layout_set("repair_floor",5) && writes==before);
 assert(!esb_relay_layout_set("max_repairs",3));assert(relay_settings.repair_floor==3);
 read_result=10;relay_settings.repair_floor=0;relay_settings_load();assert(relay_settings.repair_floor==3);
 assert(!esb_relay_layout_set("repair_floor",0));
 for(unsigned r=0;r<=5;r++){
  relay_applied_settings=(struct relay_runtime_settings){11,r,16,100,120,r};
  relay_geometry_make(&relay_receiver_geometry,11,r,16,120);
  relay_timeline_clear(&relay_timeline_active);uint32_t start=0xffff0000U;
  for(unsigned f=0;f<120;f++){
   assert(relay_frame_repairs(f)==(r<2 && f%8==0?2:r));
   relay_frame_announce(f,start);uint32_t next;
   assert(relay_timeline_start(&relay_timeline_active,f+1,&next));
   assert(next-start==relay_runtime_period(f,11,relay_frame_repairs(f),16,120));start=next;
  }
  assert(start==0xffff0000U+32768U);
 }
 /* Every R change, including maintenance, is committed two frames ahead.
  * Advancing the receiver cannot alter a start announced in the prior B. */
 for(unsigned r=0;r<=3;r++){
  relay_applied_settings=(struct relay_runtime_settings){16,r,16,100,120,r};
  relay_geometry_make(&relay_receiver_geometry,16,r,16,120);
  relay_timeline_clear(&relay_timeline_active);
  uint32_t start=0xffff0000U,committed[3]={0};
  for(unsigned f=0;f<120;f++){
   relay_frame_announce(f,start);uint32_t current[3];
   for(unsigned k=0;k<3;k++)assert(relay_timeline_start(&relay_timeline_active,f+k+1,&current[k]));
   if(f){assert(current[0]==committed[1]);assert(current[1]==committed[2]);}
   uint32_t oracle=start;
   for(unsigned k=0;k<3;k++){
    unsigned count=r<2 && (f+k)%8==0?2:r;
    unsigned cap=((uint64_t)(f+k+1)*32768U)/120U-((uint64_t)(f+k)*32768U)/120U;
    unsigned occupied=(17U+count)*16U;
    oracle+=occupied>cap?occupied:cap;assert(current[k]==oracle);
   }
   memcpy(committed,current,sizeof(current));start=current[0];
  }
 }
 assert(!mutex && !depth);puts("Runtime settings: persistence, CRC, defaults, clamp, failure atomicity, no-op and scheduled R passed");
}
'''
with tempfile.TemporaryDirectory() as directory:
    p=Path(directory);(p/'settings.c').write_text(prefix+state+function('esb_relay_layout_print')+function('esb_relay_layout_set')+cases)
    for experimental in (0,1):
        subprocess.run(shlex.split(os.environ.get('CC','cc'))+['-std=c11','-Wall','-Wextra','-Werror','-Wno-unused-function','-fsanitize=address,undefined',f'-DCONFIG_RELAY_EXPERIMENTAL_SLOT_15={experimental}','-I'+str(HERE.parents[2]/'src/connection'),str(p/'settings.c'),'-o',str(p/'settings')],check=True)
        subprocess.run([str(p/'settings')],check=True)
