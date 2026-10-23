/* SPDX-License-Identifier: MIT
 * Explicit QEMU virt Platform Expert. Real IOKit MMIO resources and PL031 RTC;
 * no CPU-on, IOMMU, storage, power or physical UMS512 support is advertised.
 */
#include <stdint.h>
#include <string.h>
#include <sys/errno.h>
#include <kern/debug.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOLib.h>
#include <IOKit/rtc/IORTCController.h>
#include <libkern/c++/OSData.h>
#include <libkern/c++/OSArray.h>

extern "C" {
void ums512_qemu_finalize_cpu_topology(void);
bool ums512_qemu_publish_root_storage(IOService *provider);
struct ums512_platform_proof {
    uint64_t started,mmio_nubs,resource_ranges,rtc_identity;
    uint64_t rtc_reads,rtc_writes,rtc_tick_verified,unsupported_resource_requests;
};
volatile struct ums512_platform_proof ums512_platform_proof;
}
static_assert(sizeof(ums512_platform_proof)==64,"public platform proof ABI");
static bool publish_qemu_rtc(IOService *provider);

class RMXQemuPlatform : public IOPlatformExpert {
    OSDeclareDefaultStructors(RMXQemuPlatform);
    IOMemoryMap *rtcMap=nullptr;
    uint64_t socBase=0,ioSpan=0;
    uint32_t rtcRead(unsigned offset);
    void rtcWrite(unsigned offset,uint32_t value);
    IOPlatformDevice *memoryNub(const char *path,unsigned rangeCount);
public:
    IOService *probe(IOService *provider,SInt32 *score) override;
    bool start(IOService *provider) override;
    bool configure(IOService *provider) override;
    void free(void) override;
    IOReturn getNubResources(IOService *nub) override;
    bool compareNubName(const IOService *nub,OSString *name,OSString **matched=nullptr) const override;
    bool getMachineName(char *name,int length) override;
    bool getModelName(char *name,int length) override;
    long getGMTTimeOfDay(void) override;
    void setGMTTimeOfDay(long seconds) override;
    int haltRestart(unsigned type) override;
};
OSDefineMetaClassAndStructors(RMXQemuPlatform,IOPlatformExpert);

IOService *RMXQemuPlatform::probe(IOService *provider,SInt32 *score)
{
    static const char expected[]="qemu,virt";
    OSData *model=provider?OSDynamicCast(OSData,provider->getProperty("model")):nullptr;
    if (!model || model->getLength()!=sizeof(expected) ||
        memcmp(model->getBytesNoCopy(),expected,sizeof(expected))) { return nullptr; }
    return IOPlatformExpert::probe(provider,score);
}
uint32_t RMXQemuPlatform::rtcRead(unsigned offset)
{
    if (!rtcMap) { panic("QEMU platform: RTC unavailable"); }
    if (!offset) { ums512_platform_proof.rtc_reads++; }
    return *reinterpret_cast<volatile uint32_t *>(rtcMap->getVirtualAddress()+offset);
}
void RMXQemuPlatform::rtcWrite(unsigned offset,uint32_t value)
{
    if (!rtcMap) { panic("QEMU platform: RTC unavailable"); }
    *reinterpret_cast<volatile uint32_t *>(rtcMap->getVirtualAddress()+offset)=value;
    __asm__ volatile("dsb sy" ::: "memory");
    if (offset==8) { ums512_platform_proof.rtc_writes++; }
}
IOPlatformDevice *RMXQemuPlatform::memoryNub(const char *path,unsigned count)
{
    IORegistryEntry *entry=IORegistryEntry::fromPath(path,gIODTPlane);
    if (!entry) { panic("QEMU platform: required DT device missing"); }
    OSData *property=OSDynamicCast(OSData,entry->getProperty("reg"));
    uint64_t reg[4];
    if (!count || count>2 || !property || property->getLength()!=count*16) {
        panic("QEMU platform: malformed device registers");
    }
    memcpy(reg,property->getBytesNoCopy(),count*16);
    OSArray *memory=OSArray::withCapacity(count);
    if (!memory) { panic("QEMU platform: MMIO resource allocation failed"); }
    for (unsigned i=0;i<count;i++) {
        uint64_t offset=reg[2*i],bytes=reg[2*i+1];
        if (bytes<0x1000 || offset>ioSpan || bytes>ioSpan-offset || socBase>UINT64_MAX-offset ||
            bytes>UINT64_MAX-(socBase+offset) || ((socBase+offset)&0xfff)) { panic("QEMU platform: MMIO outside bus range"); }
        IODeviceMemory *range=IODeviceMemory::withRange(socBase+offset,bytes);
        if (!range || !memory->setObject(range)) { panic("QEMU platform: MMIO descriptor failed"); }
        range->release();
    }
    IOPlatformDevice *nub=new IOPlatformDevice;
    if (!nub || !nub->init(entry,gIODTPlane)) { panic("QEMU platform: DT nub creation failed"); }
    entry->release();
    nub->setDeviceMemory(memory); memory->release();
    return nub;
}
bool RMXQemuPlatform::start(IOService *provider)
{
    /* Validate again at start, independent of the catalogue match. */
    SInt32 score=0;
    if (!probe(provider,&score)) { return false; }
    IORegistryEntry *bus=IORegistryEntry::fromPath("/arm-io",gIODTPlane);
    OSData *data=bus?OSDynamicCast(OSData,bus->getProperty("ranges")):nullptr;
    uint64_t ranges[3];
    if (!data || data->getLength()!=sizeof(ranges)) { panic("QEMU platform: missing bus range"); }
    memcpy(ranges,data->getBytesNoCopy(),sizeof(ranges)); bus->release();
    if (ranges[0] || !ranges[1] || !ranges[2] || ranges[2]>UINT64_MAX-ranges[1]) {
        panic("QEMU platform: unsupported bus translation");
    }
    socBase=ranges[1]; ioSpan=ranges[2];
    IOPlatformDevice *rtc=memoryNub("/arm-io/rtc",1);
    IOMemoryDescriptor *memory=rtc->getDeviceMemoryWithIndex(0);
    rtcMap=memory?memory->map(kIOMapInhibitCache):nullptr;
    rtc->release();
    if (!rtcMap) { panic("QEMU platform: RTC mapping failed"); }
    static const uint8_t identity[]={0x31,0x10,0x14,0x00,0x0d,0xf0,0x05,0xb1};
    for (unsigned i=0;i<8;i++) {
        if ((rtcRead(0xfe0+i*4)&255)!=identity[i]) { panic("QEMU platform: PL031 identity mismatch"); }
    }
    if (!(rtcRead(0x0c)&1)) { panic("QEMU platform: RTC counter disabled"); }
    rtcWrite(0x10,0); rtcWrite(0x1c,1); /* No RTC IRQ capability is advertised. */
    ums512_platform_proof.rtc_identity=1;
    uint32_t before=rtcRead(0);
    for (unsigned trial=0;trial<100;trial++) {
        IOSleep(20);
        if (static_cast<uint32_t>(rtcRead(0)-before)>0) { ums512_platform_proof.rtc_tick_verified=1; break; }
    }
    if (!ums512_platform_proof.rtc_tick_verified) { panic("QEMU platform: RTC counter failed to advance"); }
    if (!IOPlatformExpert::start(provider)) { return false; }
    if (!publish_qemu_rtc(this)) { panic("QEMU platform: IORTC service creation failed"); }
    ums512_qemu_finalize_cpu_topology();
    if (!ums512_qemu_publish_root_storage(provider)) { panic("QEMU platform: real root media unavailable"); }
    registerService();
    ums512_platform_proof.started=1;
    IOLog("RMX-QEMU: Platform Expert and PL031 RTC ready\n");
    return true;
}
bool RMXQemuPlatform::configure(IOService *provider)
{
    if (!IOPlatformExpert::configure(provider)) { return false; }
    static const char *const paths[]={"/arm-io/gic","/arm-io/uart0","/arm-io/rtc"};
    for (unsigned i=0;i<3;i++) {
        IOPlatformDevice *nub=memoryNub(paths[i],i?1:2);
        if (!nub->attach(this)) { panic("QEMU platform: cannot attach MMIO nub"); }
        nub->registerService(); nub->release();
        ums512_platform_proof.mmio_nubs++;
        ums512_platform_proof.resource_ranges+=i?1:2;
    }
    return true;
}
void RMXQemuPlatform::free(void)
{
    if (rtcMap) { rtcMap->release(); rtcMap=nullptr; }
    IOPlatformExpert::free();
}
IOReturn RMXQemuPlatform::getNubResources(IOService *nub)
{
    if (nub && nub->getDeviceMemory() && nub->getDeviceMemory()->getCount()) { return kIOReturnSuccess; }
    ums512_platform_proof.unsupported_resource_requests++;
    return kIOReturnUnsupported;
}
bool RMXQemuPlatform::compareNubName(const IOService *nub,OSString *name,OSString **matched) const
{ return IODTCompareNubName(nub,name,matched) || IOPlatformExpert::compareNubName(nub,name,matched); }
bool RMXQemuPlatform::getMachineName(char *name,int length)
{
    static const char model[]="qemu,virt";
    if (!name || length<static_cast<int>(sizeof(model))) { return false; }
    memcpy(name,model,sizeof(model)); return true;
}
bool RMXQemuPlatform::getModelName(char *name,int length) { return getMachineName(name,length); }
long RMXQemuPlatform::getGMTTimeOfDay(void) { return rtcRead(0); }
void RMXQemuPlatform::setGMTTimeOfDay(long seconds)
{
    if (seconds<0 || static_cast<uint64_t>(seconds)>UINT32_MAX) { panic("QEMU platform: RTC timestamp exceeds32 bits"); }
    rtcWrite(8,static_cast<uint32_t>(seconds));
}
int RMXQemuPlatform::haltRestart(unsigned type) { (void)type; return ENOTSUP; }

/* A genuine typed IORTC service, backed by the already mapped/verified PL031.
 * Publish readiness only after reading through this interface. Alarm/power
 * semantics are unsupported, and cannot silently report success.
 */
class RMXQemuRTC : public IORTC {
    OSDeclareDefaultStructors(RMXQemuRTC);
    RMXQemuPlatform *platform=nullptr;
public:
    bool start(IOService *provider) override;
    long getGMTTimeOfDay(void) override;
    void setGMTTimeOfDay(long seconds) override;
    void setAlarmEnable(IOOptionBits message) override;
};
OSDefineMetaClassAndStructors(RMXQemuRTC,IORTC);
bool RMXQemuRTC::start(IOService *provider)
{
    platform=OSDynamicCast(RMXQemuPlatform,provider);
    if (!platform || !IORTC::start(provider)) { return false; }
    clock_sec_t seconds; clock_nsec_t fraction;
    getUTCTimeOfDay(&seconds,&fraction);
    if (fraction || seconds>UINT32_MAX) { panic("QEMU RTC: invalid seconds-resolution calendar"); }
    registerService();
    IOService::publishResource("IORTC",this);
    return true;
}
long RMXQemuRTC::getGMTTimeOfDay(void) { return platform->getGMTTimeOfDay(); }
void RMXQemuRTC::setGMTTimeOfDay(long seconds) { platform->setGMTTimeOfDay(seconds); }
void RMXQemuRTC::setAlarmEnable(IOOptionBits message)
{
    (void)message;
    panic("QEMU RTC: alarm/power transition unsupported");
}
static bool publish_qemu_rtc(IOService *provider)
{
    RMXQemuRTC *rtc=new RMXQemuRTC;
    if (!rtc) { return false; }
    if (!rtc->init() || !rtc->attach(provider)) { rtc->release(); return false; }
    bool started=rtc->start(provider);
    if (!started) { rtc->detach(provider); }
    rtc->release();
    return started;
}
