/* SPDX-License-Identifier: MIT
 * Hardware-only IOKit contract. No MMIO access or guessed hardware services.
 * Not a working Platform Expert: start refuses activation until real firmware,
 * IRQ, clock, entropy/RTC and storage backends are implemented and qualified.
 * Kept out of the QEMU kernel; included as hardware-only source in the capsule.
 */
#if !defined(UMS512_HARDWARE_TARGET)
#error Hardware Platform Expert must not enter the QEMU configuration
#endif
#include <IOKit/IOPlatformExpert.h>
#include <libkern/c++/OSData.h>
#include <string.h>

class RMXUMS512Platform : public IOPlatformExpert {
    OSDeclareDefaultStructors(RMXUMS512Platform);
public:
    IOService *probe(IOService *provider,SInt32 *score) override;
    bool start(IOService *provider) override;
    bool getMachineName(char *name,int length) override;
    bool getModelName(char *name,int length) override;
    IOReturn getNubResources(IOService *nub) override;
};
OSDefineMetaClassAndStructors(RMXUMS512Platform,IOPlatformExpert);

IOService *RMXUMS512Platform::probe(IOService *provider,SInt32 *score)
{
    static const char expected[]="rmx3261,ums512";
    OSData *model=provider?OSDynamicCast(OSData,provider->getProperty("model")):nullptr;
    if (!model || model->getLength()!=sizeof(expected) ||
        memcmp(model->getBytesNoCopy(),expected,sizeof(expected))) { return nullptr; }
    return IOPlatformExpert::probe(provider,score);
}
bool RMXUMS512Platform::start(IOService *provider)
{
    SInt32 score=0;
    if (!probe(provider,&score)) { return false; }
    IOLog("RMX-UMS512: activation refused: physical backends unqualified\n");
    return false;
}
bool RMXUMS512Platform::getMachineName(char *name,int length)
{
    static const char model[]="rmx3261,ums512";
    if (!name || length<static_cast<int>(sizeof(model))) { return false; }
    memcpy(name,model,sizeof(model)); return true;
}
bool RMXUMS512Platform::getModelName(char *name,int length) { return getMachineName(name,length); }
IOReturn RMXUMS512Platform::getNubResources(IOService *nub)
{
    (void)nub;
    return kIOReturnUnsupported;
}
