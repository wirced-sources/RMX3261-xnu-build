/* SPDX-License-Identifier: MIT
 * Bounded RFC5652 detached CMS profile: one RSA2048 signer, SHA256, no attrs,
 * exactly the pinned laboratory leaf/root. Pins bind the approved certificate
 * extensions; signatures, issuer/serial, SPKI and validity are also checked.
 * This is neither general X.509 discovery nor Apple's chain of trust.
 */
#include "ums512_lab_codesign.h"
#include "lab_exec_trust.h"
#include "bearssl_hash.h"
#include "bearssl_rsa.h"
#include <string.h>
typedef struct { const uint8_t *p;size_t n; } Span;
typedef struct { Span tbs,issuer,subject,serial,modulus,signature;uint64_t from,to; } Cert;
static uint32_t be32(const uint8_t *p)
{ return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]; }
static uint32_t le32(const uint8_t *p)
{ return ((uint32_t)p[3]<<24)|((uint32_t)p[2]<<16)|((uint32_t)p[1]<<8)|p[0]; }
static int same(Span a,Span b) { return a.n==b.n && !memcmp(a.p,b.p,a.n); }
static void hash(const void *p,size_t n,uint8_t d[32])
{ br_sha256_context c;br_sha256_init(&c);br_sha256_update(&c,p,n);br_sha256_out(&c,d); }
static int item(Span *s,unsigned tag,Span *value,Span *whole)
{
    if(s->n<2 || s->p[0]!=tag) return 0;
    size_t h=2,n=s->p[1];
    if(n&128) {
        size_t bytes=n&127;n=0;
        if(!bytes || bytes>4 || bytes>s->n-h || !s->p[h]) return 0;
        for(size_t i=0;i<bytes;i++) n=(n<<8)|s->p[h++];
        if(n<128) return 0;
    }
    if(n>s->n-h) return 0;
    if(value) *value=(Span){s->p+h,n};
    if(whole) *whole=(Span){s->p,h+n};
    s->p+=h+n;s->n-=h+n;return 1;
}
static int literal(Span *s,const uint8_t *p,size_t n)
{ if(n>s->n || memcmp(s->p,p,n)) return 0;s->p+=n;s->n-=n;return 1; }
static const uint8_t sha256_oid[]={0x60,0x86,0x48,1,0x65,3,4,2,1};
static const uint8_t rsa_oid[]={0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,1};
static const uint8_t rsa_sha256_oid[]={0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,11};
static const uint8_t data_oid[]={0x2a,0x86,0x48,0x86,0xf7,0x0d,1,7,1};
static const uint8_t signed_oid[]={0x2a,0x86,0x48,0x86,0xf7,0x0d,1,7,2};
static int oid(Span *s,const uint8_t *expected,size_t n)
{ Span a;return item(s,6,&a,NULL) && same(a,(Span){expected,n}); }
static int alg(Span *s,const uint8_t *expected,size_t n)
{
    Span a;if(!item(s,0x30,&a,NULL) || !oid(&a,expected,n)) return 0;
    if(a.n) { static const uint8_t nil[]={5,0};if(!literal(&a,nil,2)) return 0; }
    return !a.n;
}
static int utc(Span *s,uint64_t *seconds)
{
    Span a;if(!item(s,0x17,&a,NULL) || a.n!=13 || a.p[12]!='Z') return 0;
    unsigned v[6];for(unsigned i=0;i<6;i++) {
        unsigned x=a.p[i*2],y=a.p[i*2+1];if(x<'0'||x>'9'||y<'0'||y>'9') return 0;
        v[i]=(x-'0')*10+y-'0';
    }
    unsigned year=2000+v[0];if(v[0]>=50 || v[1]<1 || v[1]>12 || v[2]<1 || v[2]>31 ||
        v[3]>23 || v[4]>59 || v[5]>59) return 0;
    static const unsigned md[]={31,28,31,30,31,30,31,31,30,31,30,31};
    unsigned max=md[v[1]-1]+((v[1]==2 && year%4==0)?1u:0u);if(v[2]>max) return 0;
    uint64_t days=0;for(unsigned y=1970;y<year;y++) days+=(y%4==0?366u:365u);
    for(unsigned m=1;m<v[1];m++) days+=md[m-1]+((m==2 && year%4==0)?1u:0u);
    days+=v[2]-1;*seconds=((days*24+v[3])*60+v[4])*60+v[5];return 1;
}
static int rsa_verify(Span modulus,Span signature,Span message)
{
    if(modulus.n!=256 || !(modulus.p[0]&128) || !(modulus.p[255]&1) || signature.n!=256) return 0;
    uint8_t n[256],e[]={1,0,1},d[32],actual[32];memcpy(n,modulus.p,256);
    br_rsa_public_key key={n,sizeof(n),e,sizeof(e)};
    static const uint8_t encoded_oid[]={9,0x60,0x86,0x48,1,0x65,3,4,2,1};
    hash(message.p,message.n,d);
    return br_rsa_i31_pkcs1_vrfy(signature.p,signature.n,encoded_oid,32,&key,actual)==1 && !memcmp(d,actual,32);
}
static int cert(Span encoded,Cert *c)
{
    Span seq,tbs,version,validity,key,bits,pub,mod,exponent,ext;
    static const uint8_t v3[]={2,1,2},e65537[]={1,0,1};
    if(!item(&encoded,0x30,&seq,NULL) || encoded.n || !item(&seq,0x30,&tbs,&c->tbs) ||
       !alg(&seq,rsa_sha256_oid,sizeof(rsa_sha256_oid)) || !item(&seq,3,&bits,NULL) || seq.n ||
       bits.n!=257 || bits.p[0]) return 0;
    c->signature=(Span){bits.p+1,bits.n-1};
    if(!item(&tbs,0xa0,&version,NULL) || !literal(&version,v3,sizeof(v3)) || version.n ||
       !item(&tbs,2,NULL,&c->serial) || !alg(&tbs,rsa_sha256_oid,sizeof(rsa_sha256_oid)) ||
       !item(&tbs,0x30,NULL,&c->issuer) || !item(&tbs,0x30,&validity,NULL) ||
       !utc(&validity,&c->from) || !utc(&validity,&c->to) || validity.n || c->from>=c->to ||
       !item(&tbs,0x30,NULL,&c->subject) || !item(&tbs,0x30,&key,NULL) ||
       !alg(&key,rsa_oid,sizeof(rsa_oid)) || !item(&key,3,&bits,NULL) || key.n || bits.n<2 || bits.p[0]) return 0;
    bits.p++;bits.n--;
    if(!item(&bits,0x30,&pub,NULL) || bits.n || !item(&pub,2,&mod,NULL) || mod.n!=257 || mod.p[0] ||
       !item(&pub,2,&exponent,NULL) || pub.n || !same(exponent,(Span){e65537,3}) ||
       !item(&tbs,0xa3,&ext,NULL) || tbs.n || !ext.n) return 0;
    c->modulus=(Span){mod.p+1,256};return 1;
}
static int cms(Span content,Span encoded,uint64_t now)
{
    Span top,wrapped,sd,digests,eci,certs,si_set,si,sid,signature,x;
    static const uint8_t one[]={2,1,1};
    if(!item(&encoded,0x30,&top,NULL) || encoded.n || !oid(&top,signed_oid,sizeof(signed_oid)) ||
       !item(&top,0xa0,&wrapped,NULL) || top.n || !item(&wrapped,0x30,&sd,NULL) || wrapped.n ||
       !literal(&sd,one,3) || !item(&sd,0x31,&digests,NULL) || !alg(&digests,sha256_oid,sizeof(sha256_oid)) || digests.n ||
       !item(&sd,0x30,&eci,NULL) || !oid(&eci,data_oid,sizeof(data_oid)) || eci.n ||
       !item(&sd,0xa0,&certs,NULL)) return 0;
    Span leaf={lab_exec_leaf,sizeof(lab_exec_leaf)},root={lab_exec_root,sizeof(lab_exec_root)};
    unsigned seen=0;
    while(certs.n) {
        if(!item(&certs,0x30,NULL,&x)) return 0;
        unsigned bit=same(x,leaf)?1u:(same(x,root)?2u:0u);
        if(!bit || (seen&bit)) return 0;seen|=bit;
    }
    if(seen!=3 || !item(&sd,0x31,&si_set,NULL) || sd.n || !item(&si_set,0x30,&si,NULL) || si_set.n ||
       !literal(&si,one,3) || !item(&si,0x30,&sid,NULL)) return 0;
    Cert lc,rc;
    if(!cert(leaf,&lc) || !cert(root,&rc) || !same(lc.issuer,rc.subject) || !same(rc.issuer,rc.subject) ||
       now<lc.from || now>lc.to || now<rc.from || now>rc.to ||
       !rsa_verify(rc.modulus,rc.signature,rc.tbs) || !rsa_verify(rc.modulus,lc.signature,lc.tbs)) return 0;
    if(!item(&sid,0x30,NULL,&x) || !same(x,lc.issuer) || !item(&sid,2,NULL,&x) || !same(x,lc.serial) || sid.n ||
       !alg(&si,sha256_oid,sizeof(sha256_oid)) || !alg(&si,rsa_oid,sizeof(rsa_oid)) ||
       !item(&si,4,&signature,NULL) || si.n) return 0;
    return rsa_verify(lc.modulus,signature,content);
}
static int directory(Span cd,uint8_t digest[32],uint32_t *limit,uint32_t *offset,uint32_t *slots)
{
    static const char init[]="org.rmx.qemu.init",child[]="org.rmx.qemu.child";
    if(cd.n<48 || be32(cd.p)!=0xfade0c02 || be32(cd.p+4)!=cd.n || be32(cd.p+8)!=0x20100 ||
       be32(cd.p+12)!=0x300 || be32(cd.p+20)!=48 || be32(cd.p+24) ||
       cd.p[36]!=32 || cd.p[37]!=2 || cd.p[38] || cd.p[39]!=14 || be32(cd.p+40) || be32(cd.p+44)) return 0;
    *offset=be32(cd.p+16);*slots=be32(cd.p+28);*limit=be32(cd.p+32);
    if(*offset>cd.n || !*limit || *limit>128*1024 ||
       *slots!=(*limit+16383)/16384 || cd.n-*offset!=(size_t)*slots*32) return 0;
    if(!((*offset==48+sizeof(init) && !memcmp(cd.p+48,init,sizeof(init))) ||
         (*offset==48+sizeof(child) && !memcmp(cd.p+48,child,sizeof(child))))) return 0;
    hash(cd.p,cd.n,digest);return 1;
}
static int superblob(Span sb,uint64_t now,Span *cd,uint8_t digest[32],uint32_t *limit,uint32_t *offset,uint32_t *slots)
{
    if(sb.n<28 || sb.n>16384 || be32(sb.p)!=0xfade0cc0 || be32(sb.p+4)!=sb.n || be32(sb.p+8)!=2 ||
       be32(sb.p+12)!=0 || be32(sb.p+16)!=28 || be32(sb.p+20)!=0x10000) return 0;
    size_t cms_at=be32(sb.p+24);
    if(cms_at<28 || cms_at>sb.n || sb.n-cms_at<8) return 0;
    *cd=(Span){sb.p+28,cms_at-28};
    if(be32(sb.p+cms_at)!=0xfade0b01 || be32(sb.p+cms_at+4)!=sb.n-cms_at ||
       !directory(*cd,digest,limit,offset,slots)) return 0;
    return cms(*cd,(Span){sb.p+cms_at+8,sb.n-cms_at-8},now);
}
int ums512_lab_verify_superblob(const uint8_t *p,size_t n,uint64_t now,uint8_t digest[32])
{ Span cd;uint32_t limit,offset,slots;return p && digest && superblob((Span){p,n},now,&cd,digest,&limit,&offset,&slots); }
int ums512_lab_verify_file(const uint8_t *p,size_t n,uint64_t now,uint8_t digest[32])
{
    if(!p || !digest || n<32 || n>256*1024 || le32(p)!=0xfeedfacf || le32(p+4)!=0x100000c || le32(p+8) || le32(p+12)!=2) return 0;
    uint32_t count=le32(p+16),size=le32(p+20);size_t at=32,signature=0,length=0;
    if(count>32 || size>n-32) return 0;
    for(uint32_t i=0;i<count;i++) {
        if(at>32+size || 32+size-at<8) return 0;
        uint32_t cmd=le32(p+at),len=le32(p+at+4);
        if(len<8 || (len&7) || len>32+size-at) return 0;
        if(cmd==0x1d) { if(signature || len!=16) return 0;signature=le32(p+at+8);length=le32(p+at+12); }
        if(cmd==0xc || cmd==0xe || cmd==0x80000028 || cmd==0x80000018 || cmd==0x8000001f || cmd==0x80000023 || cmd==0x21 || cmd==0x2c) return 0;
        at+=len;
    }
    if(at!=32+size || !signature || signature>n || length!=n-signature) return 0;
    Span cd;uint32_t limit,offset,slots;
    if(!superblob((Span){p+signature,length},now,&cd,digest,&limit,&offset,&slots) || limit!=signature) return 0;
    for(uint32_t i=0;i<slots;i++) {
        size_t begin=(size_t)i*16384,amount=limit-begin;if(amount>16384) amount=16384;
        uint8_t d[32];hash(p+begin,amount,d);if(memcmp(d,cd.p+offset+(size_t)i*32,32)) return 0;
    }
    return 1;
}
