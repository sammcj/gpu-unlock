// SPDX-License-Identifier: GPL-2.0-only
#include <assert.h>
#include <stdarg.h>
#include <sys/stat.h>
#define __KERNEL__
#include "../kernel/gpu_unlock/firmware_610.c"
#include "../kernel/gpu_unlock/unlock_610.c"
#include "vbios_fixture.h"
#include "stage1_tables.h"
static u32 regs[0x1000000/4];
static const char *asset_root;
static struct unlock_transaction_work *last_work;
static bool full_active;
static void check_published_image(void);
static void check_restored_signature(void);
static u32 payload_word(const u8 *p) { return p[0] | (u32)p[1]<<8 | (u32)p[2]<<16 | (u32)p[3]<<24; }
static struct {
    u16 cmd,saved;
    unsigned long now;
    int allocs,live,frees,fail_alloc,fail_mask,flrs,fail_reset,starts,boot_mode,bar_bad,barriers,writes;
    int gsp_starts,fwsec_mode,master_fail,master_stuck,selector_writes,ss1_writes,fw_live;
    int pending,lost_identity,corrupt_selector,alien_wpr;
    int fw_requests,fail_fw,fail_claim,fail_map,fail_save,fail_context,pins,selector_bad;
    int restore_mask_fail,late_devres;
    int group_requests,fail_group,group_live,group_before,cache_records,cache_released;
    int switch_stuck,dma_commands,dma_stall_after;
    int reset_delay,reset_reads[2],reset_pending[2],reset_post_fault;
    int reset_release_stuck,start_read_bad,cpuctl_reads;
    int reset_locked_until_flr,hold_writes,bar_ready_after,bar_ready_reads,wpr_after;
    int post_gfw,post_gfw_reads,gsp_post_reset_writes;
    int fwsec_wpr;u32 fwsec_wpr_lo,fwsec_wpr_hi; /* WPR2 that FWSEC-FRTS enables */
    int apertures,regions;
    int bound,gfw_late,gfw_late_reads; /* resume: nvidia bound; GFW done after N reads */
    int deny_wpr, deny_reset, fail_write, fail_attempt, write_nohalt, mailbox_error, stale_halt, gsp_stale_halt;
    u32 fail_address;
    int corrupt_boot_bundle;
    const char *corrupt_asset;
    int busmaster; /* the PCI core's is_busmaster */
    char log[32768];
} fake;
void *kzalloc(size_t n,int flags) {
    if(fake.fail_context)return NULL;
    last_work=calloc(1,n);return last_work;
}
void test_device_log(const char *format, ...) {
    va_list args;
    size_t at=strlen(fake.log);
    va_start(args,format);
    vsnprintf(fake.log+at,sizeof(fake.log)-at,format,args);
    va_end(args);
}
static u64 mask;
static struct pci_dev dev;
static u8 fw_image[4097];
static struct firmware fw={sizeof(fw_image),fw_image};
static void setup(struct unlock_transaction_work *w) {
    memset(&fake,0,sizeof(fake)); memset(regs,0,sizeof(regs)); memset(w,0,sizeof(*w));
    mask=0xffffffffffffull; dev=(struct pci_dev){.dev={.dma_mask=&mask,.coherent_dma_mask=0xfffffffffull},.vendor=0x10de,.device=0x2204,.refs=1};
    last_work=w; w->card=gu_card_find(dev.device);w->family=w->card->writes;w->load=gpu_unlock_610_select_firmware(w->card);
    w->pdev=&dev; w->bar=regs; w->bar_len=sizeof(regs); w->mapped=true;
    fake.cmd=2;fake.saved=2;regs[(GU_SEC2_BASE+0xf4)/4]=1u<<31;regs[(0x110000+0xf4)/4]=1u<<31;
    regs[(GU_SEC2_BASE+0x118)/4]=2;regs[(0x110000+0x118)/4]=2;
    regs[GU_FEAT_SS0_OFFSET/4]=0x88888888;regs[GU_FEAT_SS1_OFFSET/4]=0;
    regs[0x1fa824/4]=0xfffffff0;regs[0x1fa828/4]=0;
    regs[0]=0x172000a1;
}
/* Standalone Falcon transport fixture: no transaction object in its context. */
static int standalone_read(void *context,u32 offset,u32 *value) {
    assert(offset<=sizeof(regs)-4);
    *value=readl((u8 *)context+offset);
    if(fake.start_read_bad && offset==GU_SEC2_BASE+GU_FALCON_CPUCTL_OFFSET && ++fake.cpuctl_reads==2)
        *value=~0u;
    return 0;
}
static void standalone_write(void *context,u32 offset,u32 value) {
    assert(offset<=sizeof(regs)-4);
    writel(value,(u8 *)context+offset);
}
static void evidence_empty(const struct gu_falcon_evidence *e) {
    assert(!e->reset_asserted && !e->reset_released && !e->reloaded && !e->started && !e->halted);
}
static struct gu_device resolve_device(struct pci_dev *pdev) {
    const struct gu_card *recipe=gu_card_find(pdev->device);
    return (struct gu_device){pdev,recipe,gpu_unlock_610_select_firmware(recipe)};
}
void *dma_alloc_coherent(struct device *d,size_t n,dma_addr_t *a,int flags) {
    fake.allocs++; if(fake.fail_alloc==fake.allocs)return NULL;
    void *p=calloc(1,n); assert(p);
    *a=(d->coherent_dma_mask<=0xffffffffull?0x100000ull:0x100000000ull)+fake.allocs*0x10000ull;
    assert(*a+n-1<=d->coherent_dma_mask);fake.live++;return p;
}
void dma_free_coherent(struct device *d,size_t n,void *p,dma_addr_t a) {
    assert(p && a>=0x100000ull);free(p);fake.live--;fake.frees++;
}
int dma_set_mask(struct device *d,u64 v) {
    *d->dma_mask=v;return fake.fail_mask==1 || (fake.restore_mask_fail && v>0xffffffffull)?-EIO:0;
}
int dma_set_coherent_mask(struct device *d,u64 v) { d->coherent_dma_mask=v;return fake.fail_mask==2?-EIO:0; }
void dma_wmb(void) { fake.barriers++; }
void usleep_range(unsigned long a,unsigned long b) {fake.now+=a;}
ktime_t ktime_get(void) {return fake.now;}
u32 readl(const void *p) {
    size_t n=((const u8 *)p-(const u8 *)regs)/4;assert(n<ARRAY_SIZE(regs));
    /* Power-on GFW still running: the FB size appears only once it is done. */
    if(!fake.flrs && n==GU_GFW_BOOT_OFFSET/4 && fake.gfw_late && ++fake.gfw_late_reads==fake.gfw_late) {
        regs[n]=0xff;regs[0x1183a4/4]=0x6000;
    }
    if(fake.flrs && !n && fake.bar_ready_after) {
        fake.bar_ready_reads++;
        if(fake.bar_ready_after<0 || fake.bar_ready_reads<fake.bar_ready_after)
            return fake.bar_ready_after==-2?0x12345678:0xbadf0000;
    }
    if(fake.flrs && n==GU_GFW_CPUCTL_OFFSET/4 && fake.post_gfw==1 && ++fake.post_gfw_reads==5) {
        regs[GU_GFW_CPUCTL_OFFSET/4]=0x10;regs[GU_GFW_BOOT_OFFSET/4]=0xff;
    }
    int eng=n==(GU_SEC2_BASE+0x3c0)/4?0:n==0x1103c0/4?1:-1;
    if(eng>=0 && fake.reset_pending[eng] && ++fake.reset_reads[eng]>=fake.reset_delay) {
        regs[n]=1;fake.reset_pending[eng]=0;
    }
    return regs[n];
}
void writel(u32 v,void *p) {
    fake.writes++;
    size_t off=(u8 *)p-(u8 *)regs;assert(off<sizeof(regs)); regs[off/4]=v;
    if(fake.flrs && off==0x1103c0) {
        fake.gsp_post_reset_writes++;
        regs[GU_GFW_CPUCTL_OFFSET/4]=0; /* Holding GSP reset breaks RM's entry wait. */
    }
    if(off==GU_FEAT_SS0_OFFSET)fake.selector_writes++;
    if(off==GU_FEAT_SS0_OFFSET && fake.selector_bad==1)regs[off/4]=0;
    if(off==GU_FEAT_SS1_OFFSET){fake.ss1_writes++;regs[off/4]=v&0xf;} /* 4-bit register, as on the card */
    if(off==GU_FEAT_SS1_OFFSET && fake.selector_bad==2)regs[off/4]=0;
    if(off==GU_SEC2_BASE+0x118 || off==0x110118) {
        fake.dma_commands++;
        regs[off/4]=fake.dma_stall_after && fake.dma_commands>=fake.dma_stall_after?1:2;
    }
    if(off==GU_SEC2_FALCON2_BASE+0x668 || off==0x111668)regs[off/4]=fake.switch_stuck?0:1;
    if(off==0x110100 || off==0x110130) {
        fake.gsp_starts++;
        if(fake.fwsec_wpr){regs[0x1fa824/4]=fake.fwsec_wpr_lo;regs[0x1fa828/4]=fake.fwsec_wpr_hi;}
        regs[0x110100/4]=fake.fwsec_mode==1?2:0x10;
    }
    if(off==GU_SEC2_BASE+0x100 || off==GU_SEC2_BASE+0x130) {
        if(full_active)check_published_image();
        fake.starts++;
        struct unlock_transaction_work *w=last_work;
        if(fake.boot_mode==0) {
            u32 addr=w && w->payload_cpu?payload_word((u8 *)w->payload_cpu+0xf76c):GU_FEAT_PLM_OFFSET;
            u32 value=w && w->payload_cpu?payload_word((u8 *)w->payload_cpu+0xf754):~0u;
            if(addr!=fake.fail_address && fake.starts!=fake.fail_write && (!fake.fail_attempt || fake.starts!=fake.fail_attempt))
                regs[addr/4]=value;
            regs[(GU_SEC2_BASE+0x100)/4]=fake.write_nohalt?2:0x10;
            regs[GU_SEC2_RESET_PLM_OFFSET/4]=~0u;
            if(fake.mailbox_error)regs[(GU_SEC2_BASE+0x40)/4]=0x91;
            /* Booter extends WPR2. The next invocation must restore FRTS. */
            regs[GU_WPR2_ADDR_LO_OFFSET/4]-=0x100;
        }
        if(fake.boot_mode==2)regs[(GU_SEC2_BASE+0x100)/4]=~0u;
        if(fake.boot_mode==3){regs[(GU_SEC2_BASE+0x100)/4]=0x10;regs[(GU_SEC2_BASE+0x40)/4]=0x91;}
    }
    if(off==0x1103c0 && (v&1) && !fake.flrs && !fake.gsp_stale_halt)regs[0x110100/4]=0;
    if(off==GU_SEC2_BASE+0x3c0 && (v&1)) {
        if(regs[(GU_SEC2_BASE+0x100)/4]!=~0u)
            regs[(GU_SEC2_BASE+0x100)/4]=fake.stale_halt?0x10:regs[(GU_SEC2_BASE+0x100)/4]&64;
        if(fake.deny_reset)regs[off/4]=0;
    }
    if(fake.reset_release_stuck && (off==GU_SEC2_BASE+0x3c0 || off==0x1103c0) && !(v&1))regs[off/4]|=1;
    if(fake.deny_wpr && (off==GU_WPR2_ADDR_LO_OFFSET || off==GU_WPR2_ADDR_HI_OFFSET))regs[off/4]=0;
    if(fake.fail_reset==2 && (off==GU_SEC2_BASE+0x3c0 || off==0x1103c0))regs[off/4]=0;
    if(fake.fail_reset==8 && (off==GU_SEC2_BASE+0x3c0 || off==0x1103c0))regs[off/4]=0xbadf0001;
    if((off==GU_SEC2_BASE+0x3c0 || off==0x1103c0) && (v&1) && !(fake.cmd&4)) {
        fake.hold_writes++;
        int eng=off==GU_SEC2_BASE+0x3c0?0:1;
        if(fake.reset_delay) {
            regs[off/4]=0;fake.reset_reads[eng]=0;fake.reset_pending[eng]=1;
        }
        if(fake.flrs && fake.reset_post_fault) {
            regs[off/4]=fake.reset_post_fault==1?0:0xbadf0001;
            fake.reset_pending[eng]=0;
        }
        if(fake.reset_locked_until_flr && !fake.flrs) {
            regs[off/4]=0;fake.reset_pending[eng]=0;
        }
        if(fake.flrs && fake.post_gfw==4)regs[GU_GFW_CPUCTL_OFFSET/4]=0;
    }
}
void *devres_open_group(struct device *d,void *id,int flags) {
    if(++fake.group_requests==fake.fail_group)return NULL;
    assert(!fake.group_live && !id);
    fake.group_live=1;fake.group_before=d->devres_head.count;
    d->devres_head.count++; /* open group marker */
    return &fake.group_live;
}
int devres_release_group(struct device *d,void *id) {
    assert(fake.group_live && id==&fake.group_live);
    int released=d->devres_head.count-fake.group_before-1;
    fake.cache_released+=released;d->devres_head.count=fake.group_before;
    fake.group_live=0;return released;
}
int request_firmware(const struct firmware **f,const char *n,struct device *d) {
    if(++fake.fw_requests==fake.fail_fw)return -ENOENT;
    if(!asset_root)return -ENOENT;
    char path[4096];
    int length=snprintf(path,sizeof(path),"%s/%s",asset_root,strrchr(n,'/')+1);
    assert(length>0 && (size_t)length<sizeof(path));
    FILE *file=fopen(path,"rb");assert(file);
    assert(!fseek(file,0,SEEK_END));long size=ftell(file);assert(size>0);assert(!fseek(file,0,SEEK_SET));
    struct firmware *loaded=malloc(sizeof(*loaded));u8 *data=malloc(size);assert(loaded && data);
    assert(fread(data,1,size,file)==(size_t)size);fclose(file);
    if(fake.corrupt_boot_bundle && strstr(n,"booter_load_ga100.bin"))data[0]^=1;
    if(fake.corrupt_asset && strstr(n,fake.corrupt_asset)) {
        if(strstr(n,"falcon_loader") || (strstr(n,"gsp_boot_") && !strstr(n,"desc")))size--;
        else data[0]^=1;
    }
    *loaded=(struct firmware){size,data};*f=loaded;fake.fw_live++;
    /* Linux CONFIG_FW_CACHE: successful request adds a device resource;
     * release_firmware frees the image, not this suspend-cache record. */
    d->devres_head.count++;fake.cache_records++;return 0;
}
void release_firmware(const struct firmware *f) {if(f){free((void *)f->data);free((void *)f);fake.fw_live--;}}
void __module_get(void *p) {fake.pins++;}
int pci_read_config_word(struct pci_dev *p,int r,u16 *v) {*v=r==PCI_COMMAND?fake.cmd:r==PCI_VENDOR_ID?0x10de:0;return 0;}
int pci_read_config_dword(struct pci_dev *p,int r,u32 *v) {
    *v=r==PCI_VENDOR_ID?(fake.flrs && fake.lost_identity?~0u:pci_identity(p)):(u32)fake.bar_bad;return 0;
}
int pci_write_config_word(struct pci_dev *p,int r,u16 v) {assert(r==PCI_COMMAND);fake.cmd=v|(fake.master_stuck?4:0);return 0;}
int pcie_capability_read_word(struct pci_dev *p,int r,u16 *v) {*v=r==PCI_EXP_DEVSTA?fake.pending:0;return 0;}
int pcie_capability_read_dword(struct pci_dev *p,int r,u32 *v) {*v=PCI_EXP_DEVCAP_FLR;return 0;}
int pci_is_pcie(struct pci_dev *p) {return 1;}
int pci_select_bars(struct pci_dev *p,int r) {return 7;}
int pci_request_region(struct pci_dev *p,int bar,const char *n) {
    assert(!bar); /* only BAR0: the display card's framebuffer keeps BAR1 */
    if(fake.fail_claim || fake.bound)return -EBUSY; /* nvidia holds it after resume */
    fake.regions++;return 0;
}
void pci_release_region(struct pci_dev *p,int bar) {assert(!bar && fake.regions==1);fake.regions--;}
int aperture_remove_conflicting_pci_devices(struct pci_dev *p,const char *n) {
    /* The framebuffer stays through FWSEC and Booter; it goes right before FLR.
     * After resume nvidia-drm already replaced it. */
    assert(!fake.flrs && !(fake.cmd&4) && !fake.bound);
    if(full_active)assert(fake.starts==2);
    fake.apertures++;return 0;
}
int pci_enable_device_mem(struct pci_dev *p) {fake.cmd|=2;return 0;}
void pci_disable_device(struct pci_dev *p) {}
resource_size_t pci_resource_len(struct pci_dev *p,int r) {return sizeof(regs);}
void *pci_iomap(struct pci_dev *p,int r,unsigned long n) {return fake.fail_map?NULL:regs;}
void pci_iounmap(struct pci_dev *p,void *v) {}
void *pci_map_rom(struct pci_dev *p,size_t *n) {return NULL;}
void pci_unmap_rom(struct pci_dev *p,void *v) {}
int pci_save_state(struct pci_dev *p) {fake.saved=fake.cmd;return fake.fail_save?-EIO:0;}
void pci_restore_state(struct pci_dev *p) {assert(!(fake.saved&4));fake.cmd=fake.saved;}
void pci_set_master(struct pci_dev *p) {if(!fake.master_fail){fake.cmd|=4;fake.busmaster=1;}}
void pci_clear_master(struct pci_dev *p) {fake.cmd&=~4;fake.busmaster=0;}
int pcie_flr(struct pci_dev *p) {
    if(full_active)check_restored_signature();
    if(full_active)assert(fake.apertures==!fake.bound);
    fake.flrs++;
    if(fake.late_devres)p->dev.devres_head.count++;
    /* FLR releases engine reset; post-FLR assertion must work independently. */
    regs[(GU_SEC2_BASE+0x3c0)/4]=regs[0x1103c0/4]=0;
    regs[GU_GFW_CPUCTL_OFFSET/4]=0x10;
    regs[GU_GFW_PLM_OFFSET/4]=1;regs[GU_GFW_BOOT_OFFSET/4]=0xff;
    if(fake.post_gfw==1 || fake.post_gfw==2) {
        regs[GU_GFW_CPUCTL_OFFSET/4]=0;regs[GU_GFW_BOOT_OFFSET/4]=0;
    }
    if(fake.post_gfw==3)regs[GU_GFW_PLM_OFFSET/4]=0xbadf0001;
    if(fake.wpr_after!=4)regs[0x1fa824/4]=regs[0x1fa828/4]=0;
    if(fake.corrupt_selector==1)regs[GU_FEAT_SS0_OFFSET/4]=0;
    if(fake.corrupt_selector==2)regs[GU_FEAT_SS1_OFFSET/4]=0;
    if(fake.alien_wpr){regs[0x1fa824/4]=0x1000;regs[0x1fa828/4]=0x2000;}
    if(fake.wpr_after==1)regs[0x1fa824/4]=regs[0x1fa828/4]=0;
    if(fake.wpr_after==2){regs[0x1fa824/4]=0x2000;regs[0x1fa828/4]=0x1000;}
    if(fake.wpr_after==3)regs[0x1fa824/4]=0xbadf0000;
    return fake.fail_reset==1?-EIO:0;
}
struct pci_dev *pci_dev_get(struct pci_dev *p) {p->refs++;return p;}
void pci_dev_put(struct pci_dev *p) {p->refs--;}
static u64 get64(const void *p) {const u8 *s=p;u64 v=0;for(int i=7;i>=0;i--)v=(v<<8)|s[i];return v;}
static const u8 *dma_page(u64 address) {
    struct unlock_transaction_work *w=last_work;
    assert(address>=w->pages[0].dma && !((address-w->pages[0].dma)%0x10000));
    u64 index=(address-w->pages[0].dma)/0x10000;
    assert(index<w->pages_allocated && w->pages[index].dma==address);
    return w->pages[index].cpu;
}
static void check_published_image(void) {
    struct unlock_transaction_work *w=last_work;const u8 *meta=w->meta_cpu;
    assert((w->state == GU_PUBLISHED || w->state == GU_ACTIVE) && !fake.pins && (fake.cmd&4));
    assert(get64(meta)==GU_WPR_META_MAGIC && get64(meta+8)==1);
    assert(get64(meta+72)==w->payload_dma && get64(meta+80)==GU_PAYLOAD_SIZE);
    u8 expected[GU_PAYLOAD_SIZE];
    const struct gu_reg_write *entry=&w->family->privileged.entries[w->write_index];
    gu_payload_fill(expected,entry->addr,entry->value);
    assert(!memcmp(w->payload_cpu,expected,GU_PAYLOAD_SIZE));
    assert(regs[GU_WPR2_ADDR_LO_OFFSET/4]==w->frts_lo && regs[GU_WPR2_ADDR_HI_OFFSET/4]==w->frts_hi);
    assert(!fake.flrs && w->payload_dma==get64(meta+72));
    assert(get64(meta+112)==0x5f5400000ull && get64(meta+136)==0x5fada0000ull);
    assert(get64(meta+144)==0x5ffdfa000ull && get64(meta+152)==0x5ffe00000ull);
    assert(get64(meta+168)==0x5fff00000ull && get64(meta+176)==0x600000000ull);
    /* Independently walk the radix the way a firmware consumer does. Compare
     * every published image byte, including transitions across 512-entry tables. */
    u64 image_bytes=get64(meta+24);assert(image_bytes==84226048);
    for(u64 page=0,off=0;off<image_bytes;page++,off+=4096) {
        const u8 *level0=dma_page(get64(meta+16));
        const u8 *level1=dma_page(get64(level0+(page>>18)*8));
        const u8 *level2=dma_page(get64(level1+((page>>9)&511)*8));
        const u8 *leaf=dma_page(get64(level2+(page&511)*8));
        size_t bytes=image_bytes-off<4096?image_bytes-off:4096;
        assert(!memcmp(leaf,w->gsp_fw->data+w->image_span.offset+off,bytes));
        for(size_t i=bytes;i<4096;i++)assert(!leaf[i]);
    }
    assert(!memcmp(w->boot_cpu,w->boot_fw->data,w->boot_desc.image_size));
    /* The shared Booter has one signature; each device patches its own image. */
    assert(!memcmp((u8 *)w->booter_cpu+35072,w->booter_fw->data+72+60160,384));
}
static void check_restored_signature(void) {
    struct unlock_transaction_work *w=last_work;const u8 *meta=w->meta_cpu;
    assert(w->state==GU_STOCK && get64(meta+72)==w->stock_dma && get64(meta+80)==4096);
    assert(!memcmp(w->stock_cpu,w->gsp_fw->data+w->sig_span.offset,4096));
    assert(!(fake.cmd&4));
    /* All published buffers remain alive; FLR must precede engine holds. */
    assert(fake.live==fake.allocs && !fake.frees && !fake.hold_writes);
}
static void synthetic_rom(u8 *rom) {
    vbios_fixture(rom,6);
    rom[292]=0;rom[293]=4;rom[294]=9; /* GSP engine and FWSEC ucode */
    u8 *dmem=rom+684+256;
    dmem[0]=1;dmem[1]=4;dmem[2]=8;dmem[3]=2;
    vbios_w32(dmem+4,4);vbios_w32(dmem+8,32);
    dmem[36]=3;dmem[38]=64;
    vbios_w32(dmem+40,128);vbios_w32(dmem+44,44);
}
static void load_rom(const char *path) {
    u8 *rom=(u8 *)regs+0x300000;
    if(!path || !strcmp(path,"-")) { synthetic_rom(rom); return; }
    FILE *prom=fopen(path,"rb");
    assert(prom && fread(rom,1,1024*1024,prom)==1024*1024);
    assert(fgetc(prom)==EOF);fclose(prom);
}
int main(int argc, char **argv) {
    struct unlock_transaction_work w;
    setup(&w);
    struct gu_falcon_io io={.dev=&dev.dev,.context=regs,.read=standalone_read,.write=standalone_write};
    struct gu_falcon_evidence evidence;
    /* Unknown devices have no recipe or firmware fallback, even with an empty
     * shared cache. No request, PCI ownership or transaction allocation occurs. */
    dev.device=0xffff;
    struct gu_device unknown=resolve_device(&dev);
    struct gpu_unlock_610_shared empty={0};
    assert(!unknown.recipe && !unknown.firmware);
    assert(gpu_unlock_610_load_shared(&unknown,&empty)==-ENODEV);
    assert(gpu_unlock_610_unlock(&unknown,&empty,false)==-ENODEV);
    assert(!fake.fw_requests && !fake.allocs && !fake.writes && dev.refs==1);
    const u16 ids[]={0x20c2,0x2082,0x2204,0x2414,0x2484,0x2504};
    for(unsigned i=0;i<ARRAY_SIZE(ids);i++) {
        dev.device=ids[i];
        struct gu_device resolved=resolve_device(&dev);
        assert(resolved.recipe && resolved.firmware);
        assert(resolved.firmware->direct==(i<2));
        assert(!strcmp(resolved.firmware->signature_section,i<2?".fwsignature_ga100":".fwsignature_ga10x"));
        assert(resolved.firmware->boot_size==(i<2?4096:24576));
        if(i>2)assert(resolved.firmware==gpu_unlock_610_select_firmware(gu_card_find(0x2204)));
    }
    setup(&w);
    regs[0x110118/4]=0x1230;
    assert(gu_falcon_poll(&io,0x110118,2,2,100,true,NULL)==-ETIMEDOUT);
    assert(strstr(fake.log,"poll timeout: reg=0x110118 last=0x1230 mask=0x2 expected=0x2 budget_us=100"));
    assert(!strstr(fake.log,"failure unlock_610.c"));
    assert(!fake.writes);
    setup(&w);
    regs[0x110118/4]=~0u;
    assert(gu_falcon_poll(&io,0x110118,2,2,100,true,NULL)==-EIO);
    assert(strstr(fake.log,"poll inaccessible: reg=0x110118 last=0xffffffff"));
    /* Exercise the dual-core reset path, including RISC-V -> Falcon switching
     * and the documented tolerated pre-reset timeout. */
    for(int mode=0;mode<9;mode++) {
        setup(&w);
        const struct gu_falcon_engine eng={GU_SEC2_BASE,GU_SEC2_FBIF_BASE,GU_SEC2_FALCON2_BASE,false};
        regs[(GU_SEC2_BASE+0xf4)/4]|=1u<<10;
        regs[(GU_SEC2_FALCON2_BASE+0x668)/4]=mode==0?1:0x10;
        if(mode==2)regs[(GU_SEC2_FALCON2_BASE+0x668)/4]=0xbadf0001;
        if(mode==3)fake.switch_stuck=1;
        if(mode==4)regs[(GU_SEC2_BASE+0xf4)/4]|=1u<<12;
        if(mode==5)regs[(GU_SEC2_BASE+0xf4)/4]&=~(1u<<31);
        if(mode==6)regs[0]=~0u;
        if(mode==7)regs[(GU_SEC2_BASE+0x3c0)/4]=0xbadf0001;
        if(mode==8)fake.reset_release_stuck=1;
        struct unlock_transaction_work unchanged=w;
        int ret=gu_falcon_reset(&io,&eng,&evidence);
        assert(!memcmp(&w,&unchanged,sizeof(w)));
        assert(!evidence.started && !evidence.reloaded && !evidence.halted);
        assert(evidence.reset_asserted==(mode!=7));
        assert(evidence.reset_released==(mode!=7 && mode!=8));
        assert((!ret)==(mode==0 || mode==1 || mode==5));
        if(mode==1)assert(regs[(GU_SEC2_FALCON2_BASE+0x668)/4]==1);
        if(mode==5){
            assert(strstr(fake.log,"pre-reset timeout tolerated"));
            assert(strstr(fake.log,"poll timeout tolerated:"));
            assert(!strstr(fake.log,"poll timeout:"));
            assert(!strstr(fake.log,"poll_us error=-110"));
            assert(!strstr(fake.log,"failure unlock_610.c"));
        }
        assert(!fake.gsp_starts && !fake.starts && !fake.dma_commands);
    }
    for(int mode=0;mode<3;mode++) {
        setup(&w);
        if(mode==0)regs[(GU_SEC2_BASE+0x118)/4]=1;
        else fake.dma_stall_after=1;
        assert(gu_falcon_dma(&io,GU_SEC2_BASE,0,0,0x100000,mode==2?256:512,0x614)==-ETIMEDOUT);
        assert(fake.dma_commands==(mode?1:0) && fake.now<=1000100);
        if(mode==1)assert(strstr(fake.log,"Falcon DMA progress: done=256 total=512"));
    }
    for(int mode=0;mode<4;mode++) {
        setup(&w);
        const struct gu_falcon_engine eng={GU_SEC2_BASE,GU_SEC2_FBIF_BASE,GU_SEC2_FALCON2_BASE,false};
        w.plm_entry=0x8f;
        if(mode==0)regs[(GU_SEC2_FBIF_BASE+0x24)/4]=0xbadf0001;
        if(mode==1)regs[GU_SEC2_FBIF_BASE/4]=~0u;
        if(mode==2)regs[(GU_SEC2_BASE+0x100)/4]=~0u;
        if(mode==3)regs[(GU_SEC2_BASE+0x100)/4]=1u<<6; /* CPUCTL alias path */
        const struct gu_falcon_hs_image program={.dma=0x100000,.code_size=256,
            .data_off=256,.data_size=256,.engine_mask=1,.ucode_id=3};
        struct unlock_transaction_work unchanged=w;
        int ret=gu_falcon_hs(&io,&eng,&program,&evidence);
        assert(!memcmp(&w,&unchanged,sizeof(w)));
        assert(evidence.reset_asserted && evidence.reset_released);
        assert(evidence.reloaded==(mode==3) && evidence.started==(mode==3) && evidence.halted==(mode==3));
        assert((!ret)==(mode==3));
        assert(fake.starts==(mode==3?1:0));
        if(mode<2)assert(!fake.dma_commands);
    }
    /* Some GA102 boards keep GSP HALTED across reset, as RM never checks. WPR2
     * proves FWSEC ran, so only the GSP launch tolerates it; SEC2 stays strict. */
    for(int sec2=0;sec2<2;sec2++) {
        setup(&w);
        fake.gsp_stale_halt=!sec2;fake.stale_halt=sec2;
        const struct gu_falcon_engine gsp={GU_GSP_BASE,GU_GSP_FBIF_BASE,GU_GSP_FALCON2_BASE,true};
        const struct gu_falcon_engine sec={GU_SEC2_BASE,GU_SEC2_FBIF_BASE,GU_SEC2_FALCON2_BASE,false};
        regs[(sec2?GU_SEC2_BASE:GU_GSP_BASE)/4+0x40]=0x10;
        const struct gu_falcon_hs_image program={.dma=0x100000,.code_size=256,
            .data_off=256,.data_size=256,.engine_mask=1,.ucode_id=3};
        int ret=gu_falcon_hs(&io,sec2?&sec:&gsp,&program,&evidence);
        assert(sec2?ret==-ETIMEDOUT && !evidence.started:!ret && evidence.started && evidence.halted);
    }
    /* Reject DMA address truncation/wrap before any reset or transfer. */
    for(int bad=0;bad<5;bad++) {
        setup(&w);
        u32 dest=bad==0?0xffff00:0, off=bad==1?0xffffff00:0;
        dma_addr_t src=bad==2?(1ull<<49)-256:0x100000;
        u32 size=bad==3?257:512;
        if(bad==4)src++;
        assert(gu_falcon_dma(&io,GU_SEC2_BASE,dest,off,src,size,0x614)==-EINVAL);
        assert(!fake.writes);
    }
    {
        const struct gu_falcon_engine eng={GU_SEC2_BASE,GU_SEC2_FBIF_BASE,GU_SEC2_FALCON2_BASE,false};
        setup(&w);
        struct gu_falcon_hs_image program={.dma=0x100000,.code_size=256,.code_va=0x200000,
            .data_off=256,.data_size=256,.engine_mask=1,.ucode_id=3};
        evidence=(struct gu_falcon_evidence){true,true,true,true,true};
        assert(gu_falcon_hs(&io,&eng,&program,&evidence)==-ERANGE);
        evidence_empty(&evidence);
        assert(!fake.writes);
        /* Bad DMEM geometry must not leave an already-submitted IMEM DMA. */
        program.code_va=0;program.data_size=257;
        evidence=(struct gu_falcon_evidence){true,true,true,true,true};
        assert(gu_falcon_hs(&io,&eng,&program,&evidence)==-EINVAL);
        evidence_empty(&evidence);
        assert(!fake.writes);
    }
    /* All launch variants return partial evidence without changing transaction
     * policy/ownership, including submitted starts that never produce HALT. */
    for(int variant=0;variant<3;variant++)
        for(int mode=0;mode<5;mode++) {
            if(variant==2 && mode==4)continue;
            setup(&w);
            const struct gu_falcon_engine eng=variant==2?
                (struct gu_falcon_engine){GU_GSP_BASE,GU_GSP_FBIF_BASE,GU_GSP_FALCON2_BASE,true}:
                (struct gu_falcon_engine){GU_SEC2_BASE,GU_SEC2_FBIF_BASE,GU_SEC2_FALCON2_BASE,false};
            u32 words[192]={0};
            const struct gu_falcon_hs_image hs={.dma=0x100000,.code_size=256,
                .data_off=256,.data_size=256,.engine_mask=1,.ucode_id=3};
            const struct gu_falcon_direct_image direct={.words=words,.os_code_size=256,
                .app_code_off=256,.app_code_size=256,.os_data_off=512,.os_data_size=256};
            const struct gu_falcon_loader_image loader={.loader=words,.loader_size=sizeof(words),
                .dma=0x100000,.data_off=512,.imem_ns_size=256,.imem_sec_pa=256,
                .imem_sec_size=256,.dmem_size=256};
            regs[(GU_GSP_BASE+GU_FALCON_HWCFG_OFFSET)/4]=256;
            if(mode==1){fake.write_nohalt=1;fake.fwsec_mode=1;}
            if(mode==2)fake.fail_reset=2;
            if(mode==3) {
                u32 offset=variant==0?eng.fbif+GU_FBIF_CTL_OFFSET:
                    variant==1?eng.base+GU_FALCON_DMACTL_OFFSET:eng.fbif+GU_FBIF_TRANSCFG(4);
                regs[offset/4]=~0u;
            }
            if(mode==4)fake.start_read_bad=1;
            evidence=(struct gu_falcon_evidence){true,true,true,true,true};
            struct unlock_transaction_work unchanged=w;
            int ret=variant==0?gu_falcon_hs(&io,&eng,&hs,&evidence):
                variant==1?gu_falcon_direct(&io,&eng,&direct,&evidence):
                gu_falcon_loader(&io,&eng,&loader,&evidence);
            assert((!ret)==(mode==0) && !memcmp(&w,&unchanged,sizeof(w)));
            assert(evidence.reset_asserted==(mode!=2) && evidence.reset_released==(mode!=2));
            assert(evidence.reloaded==(mode<2 || mode==4));
            assert(evidence.started==(mode<2) && evidence.halted==(mode==0));
            assert(fake.starts+fake.gsp_starts==(mode<2));
            if(mode==1 || mode==2)assert(ret==-ETIMEDOUT);
            assert(!fake.allocs && !fake.live && !fake.regions && !fake.flrs && !fake.pins);
        }
    /* Generic loader validation failures must clear prior evidence before reset. */
    for(int bad=0;bad<4;bad++) {
        setup(&w);
        u32 code[192]={0};
        const struct gu_falcon_engine eng={GU_GSP_BASE,GU_GSP_FBIF_BASE,GU_GSP_FALCON2_BASE,true};
        struct gu_falcon_loader_image program={.loader=code,.loader_size=sizeof(code),.dma=0x100000};
        if(bad==0)program.loader=NULL;
        if(bad==1)program.loader_size--;
        if(bad==2)program.dma++;
        if(bad==3)program.data_off=1;
        evidence=(struct gu_falcon_evidence){true,true,true,true,true};
        assert(gu_falcon_loader(&io,&eng,&program,&evidence)==-EINVAL && !fake.writes);
        evidence_empty(&evidence);
    }
    /* Actual PROM -> descriptor -> patch -> GSP DMA/start -> WPR validation.
     * Faults after firmware access retain DMA, without starting SEC2. */
    for(int mode=0;mode<10;mode++) {
        setup(&w);
        u8 *rom=(u8 *)regs+0x300000;
        load_rom(argc>=2?argv[1]:NULL);
        struct gpu_unlock_fwsec parsed;
        assert(!gpu_unlock_vbios_fwsec(rom,1024*1024,&parsed));
        w.layout.frts_offset=0x5ffe00000ull;w.layout.wpr_end=0x5fff00000ull;
        regs[0x1fa824/4]=(u32)(w.layout.frts_offset>>12)<<4;
        regs[0x1fa828/4]=(u32)((w.layout.wpr_end-4096)>>12)<<4;
        fake.fwsec_mode=mode;
        if(mode==2)regs[(0x1400+0x0e*4)/4]=1u<<16;
        if(mode==3)regs[0x1fa828/4]=0; /* disabled, low alone matched */
        if(mode==4)regs[0x1fa828/4]+=16; /* outside reservation */
        if(mode==5)regs[0x1fa824/4]-=16;
        if(mode==6)regs[(0x8241c0+8*4)/4]=0xffff; /* unavailable fuse version */
        if(mode==7)fake.fail_alloc=1;
        if(mode==8)fake.master_fail=1;
        if(mode==9)rom[parsed.sig_off-44+37]=1; /* wrong engine mask */
        int ret=unlock_transaction_fwsec(&w);
        assert(!fake.starts && !fake.flrs);
        if(mode==0) {
            assert(!ret && fake.gsp_starts==1);
            assert(strstr(fake.log,"FWSEC WPR2:"));
        } else {
            assert(ret);
            if(mode>=6)assert(!fake.gsp_starts && !w.firmware_started);
            else assert(fake.gsp_starts==1 && w.firmware_started);
        }
        if(w.firmware_started) {
            assert(unlock_transaction_unwind(&w)==-EBUSY && w.retained && fake.live==1);
            free_coherent(&w); /* harness disposal only */
        } else assert(!unlock_transaction_unwind(&w) && !fake.live);
    }
    /* Exercise the register-to-layout adapter with the pinned image geometry.
     * A range error is pre-DMA/pre-firmware; never "fix" it by skipping bounds. */
    for(int scenario=0;scenario<8;scenario++) {
        setup(&w);
        regs[0x1183a4/4]=24*1024;
        regs[0x1fa7c8/4]=1;
        regs[0x1fa82c/4]=0xfffffff0; /* disabled MMU lock: hi < lo */
        regs[0x1fa830/4]=0;
        w.image_span.size=0x5053000;
        w.boot_desc.image_size=24576;
        if(scenario==1)regs[0x625f04/4]=(u32)(((24ull<<30)-(1ull<<20))>>16)<<8 | 8;
        if(scenario==2)regs[0x625f04/4]=8; /* valid old low workspace -> VBIOS fallback */
        if(scenario==3 || scenario==4) {
            u64 low=(24ull<<30)-((scenario==3?2ull:200ull)<<20);
            regs[0x1fa82c/4]=(u32)(low>>12)<<4;
            regs[0x1fa830/4]=(u32)(((24ull<<30)-4096)>>12)<<4;
        }
        if(scenario==5)regs[0x1183a4/4]=128; /* insufficient usable FB */
        if(scenario==6)regs[0x625f04/4]=(u32)((24ull<<30)>>16)<<8 | 8; /* beyond FB */
        /* Captured cold GA102 lock: lo=256 MiB, hi exclusive is not FB top. */
        if(scenario==7) {
            regs[0x1183a4/4]=0x6000; regs[0x625f04/4]=1; regs[0x1fa7c8/4]=0x45cb8f;
            regs[0x1fa82c/4]=0x100000; regs[0x1fa830/4]=0x5cffff0;
            w.image_span.size=84226048;
        }
        int ret=unlock_transaction_layout(&w);
        assert(ret==(scenario>=4 && scenario<=6?-ERANGE:0));
        assert(strstr(fake.log,"layout inputs: fb_mb="));
        if(scenario==4) assert(strstr(fake.log,"reservations below pre-scrubbed"));
        if(scenario==5) assert(strstr(fake.log,"usable FB below 256 MiB"));
        if(scenario==6) assert(strstr(fake.log,"VGA base at or above usable FB"));
        if(scenario==7) assert(strstr(fake.log,"mmu lock ignored: high address is not the FB top"));
        if(scenario<4 || scenario==7) {
            assert(w.layout.nonwpr_start>=w.layout_in.usable_fb-(256ull<<20));
            assert(w.layout.wpr_end<=w.layout_in.vga_base);
            assert(w.layout.heap_size>=88ull<<20);
        }
        assert(!fake.writes && !fake.allocs && !fake.starts && !fake.flrs);
    }
    /* Cold entry: completed GFW, closed PLM and WPR2 down. A used card is refused. */
    for(int mode=0;mode<3;mode++) {
        setup(&w);
        regs[GU_GFW_PLM_OFFSET/4]=1;regs[GU_GFW_BOOT_OFFSET/4]=0xff;regs[GU_GFW_CPUCTL_OFFSET/4]=0x10;
        regs[GU_FEAT_PLM_OFFSET/4]=mode==1?~0u:0x8f;
        if(mode==2)regs[0x1fa828/4]=0x5ffef0;
        int ret=unlock_transaction_gfw(&w);
        assert(ret==(mode==0?0:mode==1?-EALREADY:-EBUSY));
        assert(!fake.writes && !fake.gsp_starts);
        if(mode==2)assert(strstr(fake.log,"card already initialised since power on"));
    }
    setup(&w); dev.dev_flags=PCI_DEV_FLAGS_NO_FLR_RESET;
    assert(unlock_transaction_claim(&w)==-EOPNOTSUPP && !fake.flrs && !fake.allocs);
    /* A setter may mutate a mask before returning failure; restore both. */
    for(int fail=1;fail<=2;fail++) {
        setup(&w); fake.fail_mask=fail;
        assert(unlock_transaction_dma(&w)==-EIO);
        fake.fail_mask=0;
        assert(!unlock_transaction_unwind(&w));
        assert(mask==0xffffffffffffull && dev.dev.coherent_dma_mask==0xfffffffffull);
    }
    /* Stock restoration must preserve layout and must not republish V67. */
    {
        setup(&w);
        struct unlock_transaction_page page={.dma=0x200000};
        u8 metadata[GU_WPR_META_SIZE], stock[4096], before[GU_WPR_META_SIZE];
        w.meta_cpu=metadata;w.stock_cpu=stock;w.stock_dma=0x400000;w.stock_size=4096;
        w.payload_dma=0x300000;w.boot_dma=0x500000;w.pages=&page;w.pages_allocated=1;
        w.layout_in=(struct gpu_unlock_layout_in){.usable_fb=24ull<<30,
            .vga_base=(24ull<<30)-(1ull<<20),.frts_size=1ull<<20,
            .image_size=4097,.boot_size=24576,.nonwpr_size=1ull<<20,.heap_request=88ull<<20};
        assert(!gpu_unlock_layout(&w.layout_in,&w.layout));w.image_span.size=4097;
        w.boot_desc=(struct gpu_unlock_boot_desc){.code_offset=6144,.data_offset=2048,.image_size=24576};
        assert(!publish_signature(&w) && w.state==GU_PUBLISHED);
        assert(get64(metadata+72)==w.payload_dma && get64(metadata+80)==GU_PAYLOAD_SIZE);
        memcpy(before,metadata,sizeof(before));
        assert(!restore_stock_signature(&w) && w.state==GU_STOCK);
        assert(get64(metadata+72)==w.stock_dma && get64(metadata+80)==4096);
        assert(!memcmp(before,metadata,72) && !memcmp(before+88,metadata+88,sizeof(before)-88));
        assert(restore_stock_signature(&w)==-EINVAL && fake.barriers==2);
        assert(publish_signature(&w)==-EINVAL && fake.barriers==2);
    }
    /* Exercise every coherent-allocation failure in a real multi-page radix. */
    for(int fail=0;fail<=5;fail++) {
        setup(&w);w.gsp_fw=&fw;w.image_span.size=sizeof(fw_image);
        assert(!gpu_unlock_radix_plan(w.image_span.size,&w.radix));fake.fail_alloc=fail;
        int ret=unlock_transaction_radix(&w);
        if(fail) {
            assert(ret==-ENOMEM);
            assert(strstr(fake.log,"DMA allocation failed: asset=radix-page bytes=4096"));
        } else {
            assert(ret==0 && w.pages_allocated==5);
            assert(get64(w.pages[0].cpu)==w.pages[1].dma);
            assert(get64(w.pages[1].cpu)==w.pages[2].dma);
            assert(get64(w.pages[2].cpu)==w.pages[3].dma);
            assert(get64((u8 *)w.pages[2].cpu+8)==w.pages[4].dma);
            assert(get64((u8 *)w.pages[2].cpu+16)==0);
        }
        free_coherent(&w);assert(fake.live==0);
    }
    /* The real shared table runner, using small synthetic firmware buffers.
     * Each mode runs through restore/refill/reset/reload/start/completion.
     * No second FWSEC or FLR can appear inside this loop. */
    for(int mode=0;mode<16;mode++) {
        setup(&w);
        u8 payload[GU_PAYLOAD_SIZE],metadata[GU_WPR_META_SIZE]={0};
        w.payload_cpu=payload;w.meta_cpu=metadata;w.payload_dma=0x100100000ull;
        w.meta_dma=0x100200000ull;
        w.master=w.firmware_started=true;w.state=GU_PUBLISHED;
        w.frts_saved=true;w.frts_lo=0x2000;w.frts_hi=0x2ff0;
        w.booter_hdr=(struct gpu_unlock_booter_hdr){.app_code_off=256,.app_code_size=256,
            .os_data_off=512,.os_data_size=256,.patch_loc=512,.engine_id=1,.ucode_id=3};
        w.booter_dma=0x100000;
        const struct gu_reg_write custom[]={
            {0x1fa7cc,0xfffff0ff},{0x823804,~0u},{0x823804,~0u},{0x9a0148,~0u}};
        const struct gu_write_table table=GU_WRITE_TABLE(custom);
        if(mode==1)fake.deny_reset=1;
        if(mode==2)fake.deny_wpr=1;
        if(mode==3)fake.write_nohalt=1;
        if(mode==4)fake.boot_mode=3;
        if(mode==5)fake.fail_write=2; /* one retry, then succeeds */
        if(mode==6)fake.boot_mode=1;
        if(mode==7)fake.boot_mode=2;
        if(mode==8)fake.mailbox_error=1;
        if(mode==9){fake.stale_halt=1;regs[(GU_SEC2_BASE+0x100)/4]=16;}
        if(mode==10)fake.fail_attempt=1;
        if(mode==11)w.load=gpu_unlock_610_select_firmware(gu_card_find(0x20c2));
        if(mode==12)fake.fail_address=0x823804;
        if(mode==13)regs[0x1fa7cc/4]=0xfffff0ff;
        if(mode==14)fake.selector_bad=1;
        if(mode==15)w.load=gpu_unlock_610_select_firmware(gu_card_find(0x20c2));
        u8 image[1024]={0};w.booter_cpu=image;
        int ret=run_privileged_writes(&w,&table);
        bool success=mode==0 || mode==5 || mode==10 || mode==11 || mode==13 || mode==14 || mode==15;
        if((!ret)!=success)fprintf(stderr,"runner mode %d: %s",mode,fake.log);
        assert((!ret)==success);
        assert(!fake.flrs && !fake.gsp_starts && !fake.allocs);
        if(mode==1) {
            const char *failure=strstr(fake.log,"failure unlock_610.c:");
            assert(failure && !strstr(failure+1,"failure unlock_610.c:"));
        }
        if(success) {
            assert(fake.starts==(mode==5 || mode==10?5:4));
            assert(w.fresh && w.cleanup_complete && w.state==GU_ACTIVE);
            assert(regs[GU_WPR2_ADDR_LO_OFFSET/4]==w.frts_lo && regs[GU_WPR2_ADDR_HI_OFFSET/4]==w.frts_hi);
            assert(get64(metadata+72)==w.payload_dma && get64(metadata+80)==GU_PAYLOAD_SIZE);
            int starts=fake.starts;
            const struct gu_write_table empty={0};
            assert(!run_host_writes(&w,&empty) && fake.starts==starts);
            const struct gu_reg_write host[]={ {0x82381c,0x88888888},{0x823820,8} };
            const struct gu_write_table host_table=GU_WRITE_TABLE(host);
            int host_ret=run_host_writes(&w,&host_table);
            assert(host_ret==(mode==14?-EIO:0) && fake.starts==starts);
            if(mode==14){assert(!fake.ss1_writes);continue;}
            assert(regs[GU_FEAT_SS0_OFFSET/4]==0x88888888 && regs[GU_FEAT_SS1_OFFSET/4]==8);
        } else {
            assert(fake.starts<(mode==12?4:2) && w.state==GU_ACTIVE);
            if(mode==12)assert(fake.starts==3 && !regs[0x9a0148/4]);
            if(mode==1 || mode==2 || mode==9)assert(!fake.starts);
            if(mode==3)assert(w.target_after==0xfffff0ff && !w.invocation_halted);
            if(mode==4 || mode==8)assert(w.invocation_halted && !w.cleanup_complete);
        }
    }
    for(unsigned int count=2;count<=12;count=count==2?3:count==3?12:13) {
        setup(&w);
        u8 payload[GU_PAYLOAD_SIZE], metadata[GU_WPR_META_SIZE]={0};
        w.payload_cpu=payload;w.meta_cpu=metadata;w.payload_dma=0x300000;w.meta_dma=0x400000;
        w.master=w.firmware_started=true;w.state=GU_PUBLISHED;
        w.frts_saved=true;w.frts_lo=0x2000;w.frts_hi=0x2ff0;
        w.booter_hdr=(struct gpu_unlock_booter_hdr){.app_code_off=256,.app_code_size=256,
            .os_data_off=512,.os_data_size=256,.patch_loc=512,.engine_id=1,.ucode_id=3};
        w.booter_dma=0x100000;
        assert(!run_privileged_writes(&w,test_stage1_table(count)) && fake.starts==(int)count);
        assert(!fake.flrs && !fake.gsp_starts && !fake.allocs);
    }
    /* Failed FLR/reset/BAR checks retain allocations; success excludes fetches. */
    for(int failure=0;failure<10;failure++) {
        setup(&w);w.firmware_started=true;w.original_cmd=2;w.cmd_valid=true;
        w.payload_cpu=dma_alloc_coherent(&dev.dev,GU_PAYLOAD_SIZE,&w.payload_dma,0);
        fake.fail_reset=(failure<3 || failure==8)?failure:0;fake.bar_bad=failure==3;
        fake.pending=failure==4?PCI_EXP_DEVSTA_TRPND:0;
        fake.lost_identity=failure==5;fake.corrupt_selector=failure==6?1:failure==9?2:0;fake.alien_wpr=failure==7;
        w.state=GU_STOCK;regs[GU_FEAT_SS1_OFFSET/4]=0x8;
        int ret=unlock_transaction_reset(&w);
        if(failure==6 || failure==9) {
            /* Lost selector state fails the unlock, but proven reset permits cleanup. */
            assert(ret==-EIO && (w.state == GU_QUIESCED));
            assert(!unlock_transaction_unwind(&w) && !fake.live && !w.retained);
        } else if(failure) {
            assert(ret && !(w.state == GU_QUIESCED));
            assert(unlock_transaction_unwind(&w)==-EBUSY && w.retained && fake.live==1);
            assert(strstr(fake.log,"failure unlock_610.c:"));
            if(failure==1)assert(strstr(fake.log,"PCIe FLR returned: result=-5"));
            if(failure==3)assert(strstr(fake.log,"post-FLR BAR0: actual=0x1 expected=0"));
            /* Host harness disposal only; the kernel intentionally retains. */
            free_coherent(&w);
        } else {
            assert(!ret && (w.state == GU_QUIESCED) && fake.flrs==1);
            assert(!(regs[(GU_SEC2_BASE+0x3c0)/4]&1) && !regs[0x1103c0/4]);
            assert(!unlock_transaction_unwind(&w) && fake.live==0);
        }
    }
    /* Entire production transaction with pinned assets and a board ROM (a real
     * dump, or "-" for the synthetic fixture). Only PCI/MMIO/DMA are mocked;
     * parsers, patching and ordering are real. */
    if(argc==3) {
        asset_root=argv[2];
        full_active=true;
        static const char *cases[]={"success","already-full","context-oom","asset-1","asset-2",
            "asset-3","asset-4","asset-5","claim-busy","map-failed","save-failed",
            "dma-1","dma-6","dma-7","dma-8","dma-48","dma-last",
            "gfw-timeout","preexisting-plm","fwsec-timeout","fwsec-error","fwsec-wpr",
            "booter-timeout","booter-inaccessible","booter-halted","selector-readback",
            "flr-failed","reset-inaccessible","pci-lost","pending","wpr-alien","selector-lost","mask-restore","decode-off",
            "reset-delay10","reset-delay12","reset-never","reset-post-never","reset-post-inaccessible",
            "reset-locked-before-flr","bar-ready-late","bar-inaccessible","bar-wrong-chip",
            "wpr-disabled-zero","wpr-inverted","wpr-inaccessible",
            "post-gfw-late","post-gfw-timeout","post-gfw-inaccessible","post-gsp-resumed",
            "wpr-frts-retained","firmware-group-oom-first","firmware-group-oom-later","devres-preexisting","devres-at-handoff",
            "warm-wpr2","ss1-readback","ss1-lost","power-unknown","power-unknown-no-pm",
            "firmware-bme","firmware-bme-stuck",
            "resume-success","resume-gfw-late","resume-kept-power","resume-gsp-running",
            "resume-gfw-timeout","resume-oom","chip-mismatch","resume-chip-mismatch"};
        int total_allocations=0;
        for(unsigned scenario=0;scenario<ARRAY_SIZE(cases);scenario++) {
            setup(&w);
            load_rom(argv[1]);
            regs[0x1183a4/4]=0x6000;regs[0x625f04/4]=1;regs[0x1fa7c8/4]=0x45cb8f;
            regs[0x1fa82c/4]=0x100000;regs[0x1fa830/4]=0x5cffff0;
            regs[GU_GFW_PLM_OFFSET/4]=1;regs[GU_GFW_BOOT_OFFSET/4]=0xff;
            regs[GU_GFW_CPUCTL_OFFSET/4]=0x10;
            /* Cold values captured from the Palit card at 0000:21:00.0. */
            regs[GU_FEAT_PLM_OFFSET/4]=0xffffff8f;regs[GU_FEAT_SS0_OFFSET/4]=0x40171022;
            regs[GU_FEAT_SS1_OFFSET/4]=0x2;
            fake.fwsec_wpr=1;
            fake.fwsec_wpr_lo=(u32)(0x5ffe00000ull>>12)<<4;
            /* Real GA102 FWSEC-FRTS: 0xe1000 bytes, short of the 1 MiB reserve. */
            fake.fwsec_wpr_hi=(u32)(0x5ffee0000ull>>12)<<4;
            regs[(GU_FUSE_SEC2_UCODE1+2*4)/4]=1;
            /* FWSEC fuse: the real board ROM needs version 1, the fixture 0. */
            if(strcmp(argv[1],"-"))regs[(0x8241c0+8*4)/4]=1;
            if(scenario==1){regs[GU_FEAT_SS0_OFFSET/4]=0x88888888;regs[GU_FEAT_SS1_OFFSET/4]=0x8;}
            if(scenario==2)fake.fail_context=1;
            if(scenario>=3 && scenario<=6)fake.fail_fw=scenario-2;
            if(scenario==7)fake.corrupt_asset="gsp_boot_desc_ga102.bin";
            if(scenario==8)fake.fail_claim=1;
            if(scenario==9)fake.fail_map=1;
            if(scenario==10)fake.fail_save=1;
            if(scenario>=11 && scenario<=16) {
                const int failures[]={1,6,7,8,48,total_allocations};
                fake.fail_alloc=failures[scenario-11];
            }
            if(scenario==17)regs[GU_GFW_BOOT_OFFSET/4]=0;
            if(scenario==18)regs[GU_FEAT_PLM_OFFSET/4]=~0u;
            if(scenario==19)fake.fwsec_mode=1;
            if(scenario==20)regs[(0x1400+0x0e*4)/4]=1u<<16;
            if(scenario==21)fake.fwsec_wpr_hi=0;
            if(scenario>=22 && scenario<=24)fake.boot_mode=scenario-21;
            if(scenario==25)fake.selector_bad=1;
            if(scenario==26)fake.fail_reset=1;
            if(scenario==27)fake.fail_reset=8;
            if(scenario==28)fake.lost_identity=1;
            if(scenario==29)fake.pending=PCI_EXP_DEVSTA_TRPND;
            if(scenario==30)fake.alien_wpr=1;
            if(scenario==31)fake.corrupt_selector=1;
            if(scenario==32)fake.restore_mask_fail=1;
            if(scenario==33)fake.cmd=0;
            if(scenario==34)fake.reset_delay=10;
            if(scenario==35)fake.reset_delay=12;
            if(scenario==36)fake.fail_reset=2;
            if(scenario==37)fake.reset_post_fault=1;
            if(scenario==38)fake.reset_post_fault=2;
            if(scenario==39)fake.reset_locked_until_flr=1;
            if(scenario==40)fake.bar_ready_after=5;
            if(scenario==41)fake.bar_ready_after=-1;
            if(scenario==42)fake.bar_ready_after=-2;
            if(scenario>=43 && scenario<=45)fake.wpr_after=scenario-42;
            if(scenario>=46 && scenario<=49)fake.post_gfw=scenario-45;
            if(scenario==50)fake.wpr_after=4;
            if(scenario==51)fake.fail_group=1;
            if(scenario==52)fake.fail_group=3;
            if(scenario==53)dev.dev.devres_head.count=1;
            if(scenario==54)fake.late_devres=1;
            if(scenario==55)regs[0x1fa828/4]=fake.fwsec_wpr_hi; /* a driver already ran FWSEC */
            if(scenario==56)fake.selector_bad=2;
            if(scenario==57)fake.corrupt_selector=2;
            if(scenario==58 || scenario==59)dev.current_state=PCI_UNKNOWN;
            if(scenario==58)dev.pm_cap=0x60;
            if(scenario==60 || scenario==61)fake.cmd=6; /* firmware left BME set */
            if(scenario==61)fake.master_stuck=1;
            /* After resume: nvidia bound with its BME and device resources,
             * the card powered off and on again. */
            bool bound=!strncmp(cases[scenario],"resume-",7);
            if(bound){fake.bound=1;fake.cmd=6;fake.busmaster=1;dev.dev.devres_head.count=1;}
            if(!strcmp(cases[scenario],"resume-gfw-late")) {
                fake.gfw_late=5;regs[GU_GFW_BOOT_OFFSET/4]=0;regs[0x1183a4/4]=0;
            }
            if(!strcmp(cases[scenario],"resume-kept-power")) {
                regs[GU_FEAT_SS0_OFFSET/4]=0x88888888;regs[GU_FEAT_SS1_OFFSET/4]=0x8;
            }
            if(!strcmp(cases[scenario],"resume-gsp-running")) { /* GSP-RM up: not halted, WPR2 enabled */
                regs[0x1fa828/4]=fake.fwsec_wpr_hi;regs[GU_GFW_CPUCTL_OFFSET/4]=0;
            }
            if(!strcmp(cases[scenario],"resume-gfw-timeout"))regs[GU_GFW_BOOT_OFFSET/4]=0;
            if(!strcmp(cases[scenario],"resume-oom"))fake.fail_alloc=1;
            if(strstr(cases[scenario],"chip-mismatch"))regs[0]=0x174000a1;
            /* As main.c: the GSP file is loaded once, ahead of every card. */
            struct gpu_unlock_610_shared shared={0};last_work=NULL;
            struct gu_device device=resolve_device(&dev);
            int ret=gpu_unlock_610_load_shared(&device,&shared);
            int prepared_requests=fake.fw_requests;
            struct gpu_unlock_610_shared snapshot=shared;
            u8 before[3][SHA256_DIGEST_SIZE],after[SHA256_DIGEST_SIZE];
            const struct firmware *images[]={shared.ga10x.gsp,shared.ga10x.boot,shared.booter};
            if(!scenario)
                for(unsigned i=0;i<ARRAY_SIZE(images);i++)sha256(images[i]->data,images[i]->size,before[i]);
            if(!ret)ret=gpu_unlock_610_unlock(&device,&shared,bound);
            assert(fake.fw_requests==prepared_requests && !memcmp(&shared,&snapshot,sizeof(shared)));
            if(!scenario)
                for(unsigned i=0;i<ARRAY_SIZE(images);i++) {
                    sha256(images[i]->data,images[i]->size,after);
                    assert(!memcmp(before[i],after,sizeof(after)));
                }
            gpu_unlock_610_release_shared(&shared);
            bool expected=scenario<2 || (scenario>=33 && scenario<=35) || scenario==39 || scenario==40 || scenario==43 || scenario==46 ||
                scenario==58 || scenario==60 ||
                !strcmp(cases[scenario],"resume-success") || !strcmp(cases[scenario],"resume-gfw-late");
            bool retained=fake.pins;
            if((!ret)!=expected)fprintf(stderr,"%s\n%s: error=%d\n",fake.log,cases[scenario],ret);
            assert((!ret)==expected);
            if(expected) {
                assert(fake.gsp_starts==1 && fake.starts==2 && fake.flrs==1 && !fake.pins);
                assert(fake.apertures==!bound && !fake.regions);
                assert(fake.selector_writes==1 && fake.ss1_writes==1);
                assert(regs[GU_FEAT_SS0_OFFSET/4]==0x88888888 && regs[GU_FEAT_SS1_OFFSET/4]==0x8);
                assert(mask==0xffffffffffffull && dev.dev.coherent_dma_mask==0xfffffffffull);
                /* Mirror Linux really_probe: driver entry rejects nonempty devres.
                 * A bound driver keeps its own. */
                assert(dev.dev.devres_head.count==(bound?1u:0u));
                assert(fake.cache_records==4 && fake.cache_released==4);
                /* Pinned RM checks GSP halt + readable completed GFW BEFORE
                 * its own reset/bootstrap. Preserve that entry contract. */
                assert((regs[GU_GFW_CPUCTL_OFFSET/4]&0x10) && (regs[GU_GFW_PLM_OFFSET/4]&1));
                assert((regs[GU_GFW_BOOT_OFFSET/4]&0xff)==0xff && !regs[0x1103c0/4]);
                assert(!(regs[0x1fa828/4]>>4)); /* Stock RM rejects any active WPR2. */
                if(!scenario)total_allocations=fake.allocs;
            }
            if(scenario>=34 && scenario<=50 && scenario!=36) {
                assert(fake.starts==2 && fake.flrs==1);
                if(!expected)assert(retained && !(last_work->state == GU_QUIESCED));
                if(scenario==41 || scenario==42)assert(!fake.hold_writes && ret==-ETIMEDOUT);
                if(scenario==39)assert(fake.hold_writes==1);
                if(scenario==47 || scenario==48)assert(!fake.hold_writes && ret==-ETIMEDOUT);
            }
            assert(!fake.gsp_post_reset_writes);
            assert(fake.gsp_starts<=1 && fake.starts<=2 && fake.flrs<=1 && fake.pins<=1);
            assert(fake.selector_writes<=1 && fake.ss1_writes<=1);
            if(retained) {
                assert(last_work->retained && fake.live>0 && dev.refs==2);
                /* Harness-only disposal of intentionally retained production state. */
                last_work->firmware_started=false;fake.restore_mask_fail=0;
                assert(!unlock_transaction_unwind(last_work));
                pci_dev_put(last_work->pdev);free(last_work);
            }
            /* A card whose BME will not clear is left as found; nvidia gets its own back. */
            assert(!fake.live && !fake.fw_live && dev.refs==1 && !!(fake.cmd&4)==(scenario==61 || bound));
            if(bound)assert(fake.busmaster);
            assert(!fake.group_live && fake.cache_records==fake.cache_released);
            assert(dev.dev.devres_head.count==(scenario==53 || scenario==54 || bound?1u:0u));
            assert(dev.dev.dma_mask==&mask && mask==0xffffffffffffull && dev.dev.coherent_dma_mask==0xfffffffffull);
            if(!strcmp(cases[scenario],"resume-gfw-late"))assert(fake.gfw_late_reads>=fake.gfw_late);
            /* A card that kept power or runs GSP-RM is only read. */
            if(!strcmp(cases[scenario],"resume-kept-power") || !strcmp(cases[scenario],"resume-gsp-running")) {
                assert(ret==(cases[scenario][7]=='k'?-EALREADY:-EBUSY));
                assert(!fake.writes && !fake.allocs && fake.fw_requests==4 && fake.cmd==6 && !fake.now);
            }
            if(!strcmp(cases[scenario],"resume-gfw-timeout"))
                assert(ret==-ETIMEDOUT && !fake.writes && !fake.allocs && fake.cmd==6);
            if(!strcmp(cases[scenario],"resume-oom"))
                assert(ret==-ENOMEM && !fake.gsp_starts && !fake.flrs && fake.cmd==6);
            if(scenario>=51 && scenario<=53)assert(!fake.writes && !fake.allocs && !fake.flrs);
            if(scenario==53)assert(fake.fw_requests==4 && ret==-EBUSY); /* only the shared load */
            if(scenario==3 || scenario==51)assert(!last_work && fake.fw_requests==(scenario==3));
            if(scenario==54)assert(fake.flrs==1 && ret==-EBUSY);
            if(scenario==53 || scenario==54)assert(strstr(fake.log,"driver probe resources: phase=handoff empty=0"));
            if(scenario==33)assert(fake.cmd==0);
            if(scenario==56)assert(ret==-EIO && retained && fake.ss1_writes==1 && !fake.flrs);
            if(scenario==57)assert(ret==-EIO && !retained && fake.flrs==1);
            if(scenario==59)assert(ret==-EOPNOTSUPP && !fake.allocs && !fake.flrs);
            if(scenario==60)assert(strstr(fake.log,"claim: cleared firmware BME"));
            if(scenario==61)assert(ret==-EBUSY && !fake.allocs && !fake.flrs);
            if(strstr(cases[scenario],"chip-mismatch"))
                assert(ret==-ENODEV && !fake.writes && !fake.allocs && !fake.gsp_starts && !fake.flrs);
            if(scenario==55) {
                assert(ret==-EBUSY && !retained && !fake.gsp_starts && !fake.starts && !fake.flrs);
                assert(strstr(fake.log,"card already initialised since power on"));
            }
            printf("full transaction %s: error=%d retained=%u PASS\n",cases[scenario],ret,retained);
        }
        setup(&w);
        dev.device=0x20c2;regs[0]=0x170000a1;
        regs[0x110108/4]=256; /* generic loader's IMEM size in blocks */
        vbios_fixture_v2((u8 *)regs+0x300000);
        regs[0x1183a4/4]=8192;regs[0x625f04/4]=1;regs[0x1fa7c8/4]=1;
        regs[0x1fa82c/4]=0xfffffff0;regs[0x1fa830/4]=0;
        regs[GU_GFW_PLM_OFFSET/4]=1;regs[GU_GFW_BOOT_OFFSET/4]=0xff;
        regs[GU_GFW_CPUCTL_OFFSET/4]=16;
        regs[GU_FEAT_PLM_OFFSET/4]=0xffffff8f;regs[GU_FEAT_SS0_OFFSET/4]=0;
        fake.fwsec_wpr=1;fake.fwsec_wpr_lo=0x1ffe000;
        fake.fwsec_wpr_hi=0x1ffeff0;
        struct gpu_unlock_610_shared ga100_shared={0};
        struct gu_device ga100_device=resolve_device(&dev);
        assert(!gpu_unlock_610_load_shared(&ga100_device,&ga100_shared));
        full_active=false; /* GA100 has different image/layout; runner assertions still apply. */
        int ga100_ret=gpu_unlock_610_unlock(&ga100_device,&ga100_shared,false);
        if(ga100_ret)fprintf(stderr,"GA100 full: %s",fake.log);
        assert(!ga100_ret && fake.gsp_starts==1 && fake.starts==12 && fake.flrs==1);
        assert(!fake.live && fake.fw_live==4); /* shared firmware is still alive */
        gpu_unlock_610_release_shared(&ga100_shared);
        assert(!fake.fw_live && !fake.pins && !fake.regions && dev.refs==1);
        puts("GA100 v2 FWSEC + direct SEC2 full family transaction PASS");

        /* Common immutable firmware is requested once across families.
         * Each transaction still patches a separate device DMA allocation. */
        setup(&w);
        struct gpu_unlock_610_shared cached={0};
        struct gu_device device=resolve_device(&dev);
        assert(!gpu_unlock_610_load_shared(&device,&cached) && fake.fw_requests==4);
        const struct firmware *booter=cached.booter;
        assert(booter && cached.booter_hdr.patch_loc==35072);
        struct pci_dev other=dev;
        other.device=0x2484;
        struct gu_device other_device=resolve_device(&other);
        assert(!gpu_unlock_610_load_shared(&other_device,&cached) && fake.fw_requests==4);
        other.device=0x20c2;
        other_device=resolve_device(&other);
        assert(!gpu_unlock_610_load_shared(&other_device,&cached) && fake.fw_requests==8);
        const struct firmware *loader=cached.loader;
        assert(loader && cached.booter==booter);
        assert(!gpu_unlock_610_load_shared(&other_device,&cached) && fake.fw_requests==8);
        struct unlock_transaction_work separate[2]={0};
        for(int i=0;i<2;i++) {
            separate[i].pdev=i?&other:&dev;
            separate[i].bar=regs;separate[i].bar_len=sizeof(regs);separate[i].mapped=true;
            separate[i].booter_fw=booter;separate[i].loader_fw=loader;
            separate[i].booter_hdr=cached.booter_hdr;
            separate[i].booter_image_size=GU_BOOTER_IMAGE_SIZE;
            separate[i].booter_cpu=dma_alloc_coherent(&separate[i].pdev->dev,GU_BOOTER_IMAGE_SIZE,&separate[i].booter_dma,0);
            memcpy(separate[i].booter_cpu,booter->data+72,GU_BOOTER_IMAGE_SIZE);
            assert(!patch_booter(&separate[i]));
        }
        assert(separate[0].booter_dma!=separate[1].booter_dma);
        ((u8 *)separate[0].booter_cpu)[0]^=1;
        assert(((u8 *)separate[1].booter_cpu)[0]==booter->data[72]);
        assert(!unlock_transaction_unwind(&separate[0]) && fake.fw_live==6);
        assert(!unlock_transaction_unwind(&separate[1]) && fake.fw_live==6 && !fake.live);
        gpu_unlock_610_release_shared(&cached);
        assert(!fake.fw_live && !cached.booter && !cached.loader && !cached.ga10x.gsp && !cached.ga100.gsp);
        puts("shared Booter/loader ownership and private DMA buffers PASS");

        /* Failure at every family request leaves the other completed set usable.
         * Repeat both selection orders, and reject malformed formats before dispatch. */
        for(int healthy_direct=0;healthy_direct<2;healthy_direct++) {
            static const char *bad_ga100[]={"gsp_tu10x.bin","gsp_boot_ga100.bin",
                "gsp_boot_desc_ga100.bin","falcon_loader.bin"};
            static const char *bad_ga10x[]={"gsp_ga10x.bin","gsp_boot_ga102.bin",
                "gsp_boot_desc_ga102.bin"};
            int requests=healthy_direct?3:4;
            for(int malformed=0;malformed<2;malformed++)
                for(int fail=1;fail<=requests;fail++) {
                    setup(&w);
                    dev.device=healthy_direct?0x20c2:0x2204;
                    struct gpu_unlock_610_shared mixed={0};
                    struct gu_device healthy_device=resolve_device(&dev);
                    assert(!gpu_unlock_610_load_shared(&healthy_device,&mixed));
                    struct gpu_unlock_610_firmware *healthy=healthy_direct?&mixed.ga100:&mixed.ga10x;
                    struct gpu_unlock_610_firmware *failed=healthy_direct?&mixed.ga10x:&mixed.ga100;
                    struct gpu_unlock_610_firmware saved=*healthy;
                    int live_before=fake.fw_live;
                    other=dev;other.device=healthy_direct?0x2204:0x20c2;
                    struct gu_device failed_device=resolve_device(&other);
                    if(malformed)fake.corrupt_asset=healthy_direct?bad_ga10x[fail-1]:bad_ga100[fail-1];
                    else fake.fail_fw=fake.fw_requests+fail;
                    assert(gpu_unlock_610_load_shared(&failed_device,&mixed)<0);
                    assert(failed->prepared && failed->error && !failed->gsp && !failed->boot);
                    assert(!memcmp(healthy,&saved,sizeof(saved)) && fake.fw_live==live_before);
                    int requested=fake.fw_requests;
                    assert(gpu_unlock_610_load_shared(&failed_device,&mixed)==failed->error);
                    assert(!gpu_unlock_610_load_shared(&healthy_device,&mixed) && fake.fw_requests==requested);
                    gpu_unlock_610_release_shared(&mixed);
                    assert(!fake.fw_live && !fake.live && !fake.group_live);
                    assert(fake.cache_records==fake.cache_released);
                }
        }
        puts("family request/format failures preserve prepared sibling assets PASS");

        setup(&w);
        device=resolve_device(&dev);
        fake.corrupt_boot_bundle=1;
        assert(gpu_unlock_610_load_shared(&device,&cached)==-EINVAL);
        assert(!cached.booter && !cached.ga10x.gsp && fake.fw_live==0);
        fake.corrupt_boot_bundle=0;
        /* Failed preparation stays failed until the next coordination round. */
        assert(gpu_unlock_610_load_shared(&device,&cached)==-EINVAL && fake.fw_requests==4);
        gpu_unlock_610_release_shared(&cached);
        assert(!gpu_unlock_610_load_shared(&device,&cached) && fake.fw_requests==8);
        gpu_unlock_610_release_shared(&cached);
        assert(!fake.fw_live && fake.cache_records==fake.cache_released);
        puts("pinned firmware full BF16 transactions passed under mocked hardware");
    }
    puts("actual unlock_transaction radix, early-PLM and reset/retention checks passed");
}
