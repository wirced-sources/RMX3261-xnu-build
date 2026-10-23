/* SPDX-License-Identifier: MIT
 * Genuine read-only block transport for a kernel-pinned, data-only HFS image.
 * This is QEMU laboratory media, not UMS512 storage or Apple sealed-root trust.
 */
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/conf.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IOBSD.h>
#include <IOKit/storage/IOStorage.h>
#include <IOKit/storage/IOMedia.h>
#include <libkern/crypto/sha2.h>
#include <libkern/c++/OSData.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSSet.h>
#include <pexpert/pexpert.h>
#include "root_image.h"

extern "C" const unsigned char ums512_root_image[];
extern "C" const unsigned char ums512_root_image_end[];
extern "C" {
struct ums512_storage_proof {
    uint64_t started, image_authenticated, reads, bytes_read;
    uint64_t writes_rejected, bounds_rejected, root_auth_ok, root_auth_denied;
    uint64_t test_complete, test_reads, test_writes, test_bounds;
    uint64_t test_access, test_crypto_negative, test_auth_negative, reserved;
};
volatile struct ums512_storage_proof ums512_storage_proof;
}
static_assert(sizeof(ums512_storage_proof)==128,"public storage proof ABI");
static IOMedia *rootMedia;
static void ums512_qemu_storage_selftest(IOStorage *storage);
extern "C" int ums512_qemu_hfs_root_auth(dev_t device,int isRoot,int readOnly);

static bool authenticate_image(void)
{
    SHA256_CTX context;
    unsigned char actual[32];
    SHA256_Init(&context);
    SHA256_Update(&context,ums512_root_image,RMX_ROOT_BYTES);
    SHA256_Final(actual,&context);
    return memcmp(actual,root_sha256,sizeof(actual))==0;
}

class RMXQemuRootStorage : public IOStorage {
    OSDeclareDefaultStructors(RMXQemuRootStorage);
    OSSet *readers=nullptr;
public:
    bool start(IOService *provider) override;
    void free(void) override;
    bool handleOpen(IOService *client,IOOptionBits options,void *access) override;
    bool handleIsOpen(const IOService *client) const override;
    void handleClose(IOService *client,IOOptionBits options) override;
    void read(IOService *client,UInt64 offset,IOMemoryDescriptor *buffer,
              IOStorageAttributes *attributes,IOStorageCompletion *completion) override;
    void write(IOService *client,UInt64 offset,IOMemoryDescriptor *buffer,
               IOStorageAttributes *attributes,IOStorageCompletion *completion) override;
    IOReturn synchronize(IOService *client,UInt64 start,UInt64 count,IOStorageSynchronizeOptions options=0) override;
};
OSDefineMetaClassAndStructors(RMXQemuRootStorage,IOStorage);

bool RMXQemuRootStorage::start(IOService *provider)
{
    OSData *model=provider?OSDynamicCast(OSData,provider->getProperty("model")):nullptr;
    static const char expected[]="qemu,virt";
    if (!model || model->getLength()!=sizeof(expected) ||
        memcmp(model->getBytesNoCopy(),expected,sizeof(expected))) { return false; }
    if (reinterpret_cast<uintptr_t>(ums512_root_image_end)-reinterpret_cast<uintptr_t>(ums512_root_image)!=RMX_ROOT_BYTES ||
        !IOStorage::start(provider) || !authenticate_image()) { return false; }
    readers=OSSet::withCapacity(2);
    if (!readers) { return false; }
    IOMedia *media=new IOMedia;
    if (!media || !media->init(0,RMX_ROOT_BYTES,512,0,true,false,"Apple_HFS") || !media->attach(this)) {
        OSSafeReleaseNULL(media); return false;
    }
    media->setName("RMXQemuRoot");
    media->setLocation("0");
    media->setProperty("RMX laboratory immutable root",true);
    rootMedia=media; /* Boot-lifetime object, held by this transport. */
    ums512_storage_proof.image_authenticated=1;
    int selftest=0;
    if (PE_parse_boot_argn("ums512-selftest",&selftest,sizeof(selftest)) && selftest==1) {
        ums512_qemu_storage_selftest(this);
    }
    registerService();
    media->registerService();
    ums512_storage_proof.started=1;
    IOLog("RMX-QEMU: pinned read-only HFS block medium published\n");
    return true;
}
void RMXQemuRootStorage::free(void)
{
    OSSafeReleaseNULL(readers);
    IOStorage::free();
}
bool RMXQemuRootStorage::handleOpen(IOService *client,IOOptionBits options,void *access)
{
    return client && !options && reinterpret_cast<uintptr_t>(access)==kIOStorageAccessReader && readers && readers->setObject(client);
}
bool RMXQemuRootStorage::handleIsOpen(const IOService *client) const
{
    return readers && (client?readers->containsObject(client):readers->getCount()!=0);
}
void RMXQemuRootStorage::handleClose(IOService *client,IOOptionBits options)
{
    (void)options;
    if (readers && client) { readers->removeObject(client); }
}
void RMXQemuRootStorage::read(IOService *client,UInt64 offset,IOMemoryDescriptor *buffer,
                            IOStorageAttributes *attributes,IOStorageCompletion *completion)
{
    if (!client || !buffer || !isOpen(client)) { complete(completion,kIOReturnNotOpen,0); return; }
    if (attributes && (attributes->options&~(kIOStorageOptionForceUnitAccess|kIOStorageOptionIsStatic))) {
        complete(completion,kIOReturnUnsupported,0); return;
    }
    UInt64 length=buffer->getLength();
    if (offset>RMX_ROOT_BYTES || length>RMX_ROOT_BYTES-offset || (offset&511) || (length&511)) {
        ums512_storage_proof.bounds_rejected++;
        complete(completion,kIOReturnBadArgument,0); return;
    }
    if (!(buffer->getDirection()&kIODirectionIn)) { complete(completion,kIOReturnBadArgument,0); return; }
    UInt64 actual=buffer->writeBytes(0,ums512_root_image+offset,length);
    if (actual!=length) { complete(completion,kIOReturnUnderrun,actual); return; }
    ums512_storage_proof.reads++;
    ums512_storage_proof.bytes_read+=actual;
    complete(completion,kIOReturnSuccess,actual);
}
void RMXQemuRootStorage::write(IOService *client,UInt64 offset,IOMemoryDescriptor *buffer,
                             IOStorageAttributes *attributes,IOStorageCompletion *completion)
{
    (void)client; (void)offset; (void)buffer; (void)attributes;
    ums512_storage_proof.writes_rejected++;
    complete(completion,kIOReturnNotWritable,0);
}
IOReturn RMXQemuRootStorage::synchronize(IOService *client,UInt64 start,UInt64 count,IOStorageSynchronizeOptions options)
{
    if (!client || !isOpen(client)) { return kIOReturnNotOpen; }
    if (options) { return kIOReturnUnsupported; }
    if (start>RMX_ROOT_BYTES || count>RMX_ROOT_BYTES-start) { return kIOReturnBadArgument; }
    /* Immutable memory has no dirty writes or volatile device cache to flush. */
    return kIOReturnSuccess;
}

extern "C" bool ums512_qemu_publish_root_storage(IOService *provider)
{
    RMXQemuRootStorage *storage=new RMXQemuRootStorage;
    if (!storage) { return false; }
    if (!storage->init() || !storage->attach(provider)) { storage->release(); return false; }
    bool ready=storage->start(provider);
    if (!ready) { storage->detach(provider); }
    storage->release();
    return ready;
}

extern "C" int ums512_qemu_hfs_root_auth(dev_t device,int isRoot,int readOnly)
{
    /* Never authorize a different device, vnode, mutable media or new image.
     * Authenticate actual bytes again, not a caller-supplied digest/property.
     */
    OSNumber *maj=rootMedia?OSDynamicCast(OSNumber,rootMedia->getProperty(kIOBSDMajorKey)):nullptr;
    OSNumber *min=rootMedia?OSDynamicCast(OSNumber,rootMedia->getProperty(kIOBSDMinorKey)):nullptr;
    if (device==NODEV || !isRoot || !readOnly || !rootMedia || rootMedia->isWritable() || !maj || !min ||
        static_cast<uint32_t>(major(device))!=maj->unsigned32BitValue() ||
        static_cast<uint32_t>(minor(device))!=min->unsigned32BitValue() || !authenticate_image()) {
        ums512_storage_proof.root_auth_denied++;
        return EAUTH;
    }
    ums512_storage_proof.root_auth_ok++;
    return 0;
}

static __attribute__((noinline)) void ums512_qemu_storage_selftest(IOStorage *storage)
{
    IOBufferMemoryDescriptor *buffer=IOBufferMemoryDescriptor::withCapacity(512,kIODirectionIn);
    if (!buffer || !storage->open(storage,0,kIOStorageAccessReader)) { panic("QEMU storage: test open failed"); }
    UInt64 actual=0;
    const UInt64 offsets[]={1024,RMX_ROOT_BYTES-512};
    for (UInt64 offset : offsets) {
        if (storage->read(storage,offset,buffer,nullptr,&actual)!=kIOReturnSuccess || actual!=512 ||
            memcmp(buffer->getBytesNoCopy(),ums512_root_image+offset,512)) {
            panic("QEMU storage: real block read mismatch");
        }
        ums512_storage_proof.test_reads++;
    }
    if (storage->write(storage,0,buffer,nullptr,&actual)!=kIOReturnNotWritable || actual) {
        panic("QEMU storage: immutable device accepted write");
    }
    ums512_storage_proof.test_writes++;
    const UInt64 invalid[]={RMX_ROOT_BYTES,UINT64_MAX,1};
    for (UInt64 offset : invalid) {
        if (storage->read(storage,offset,buffer,nullptr,&actual)!=kIOReturnBadArgument || actual) {
            panic("QEMU storage: invalid range accepted");
        }
        ums512_storage_proof.test_bounds++;
    }
    IOStorageAttributes attrs={};
    attrs.options=kIOStorageOptionIsEncrypted;
    if (storage->read(storage,0,buffer,&attrs,&actual)!=kIOReturnUnsupported || actual) {
        panic("QEMU storage: unsupported encrypted IO accepted");
    }
    ums512_storage_proof.test_access++;
    storage->close(storage);
    if (storage->read(storage,0,buffer,nullptr,&actual)!=kIOReturnNotOpen || actual ||
        storage->open(storage,0,kIOStorageAccessReaderWriter)) {
        panic("QEMU storage: invalid access accepted");
    }
    ums512_storage_proof.test_access++;
    buffer->release();
    /* Reject genuine SHA-256 of an image with one modified filesystem byte.
     * Stream that byte through the real hash provider; do not mutate RO media.
     */
    SHA256_CTX context;
    unsigned char altered=ums512_root_image[1024]^1, digest[32];
    SHA256_Init(&context);
    SHA256_Update(&context,ums512_root_image,1024);
    SHA256_Update(&context,&altered,1);
    SHA256_Update(&context,ums512_root_image+1025,RMX_ROOT_BYTES-1025);
    SHA256_Final(digest,&context);
    if (!memcmp(digest,root_sha256,sizeof(digest))) { panic("QEMU storage: corrupt image authenticated"); }
    ums512_storage_proof.test_crypto_negative++;
    for (unsigned mode=0;mode<3;mode++) {
        if (!ums512_qemu_hfs_root_auth(static_cast<dev_t>(-1),mode!=0,mode!=1)) {
            panic("QEMU storage: unauthorized root accepted");
        }
        ums512_storage_proof.test_auth_negative++;
    }
    ums512_storage_proof.test_complete=1;
}
