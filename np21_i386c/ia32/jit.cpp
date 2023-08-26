//#include "compiler.h"
//#include "dosio.h"
#include "cpu.h"
#include "ia32.mcr"

#include "inst_table.h"

#include "jit.h"

#include "paging.h"

#include <windows.h>

#if defined(ENABLE_TRAP)
#include "trap/steptrap.h"
#endif

#if defined(SUPPORT_ASYNC_CPU)
#include "timing.h"
#include "nevent.h"
#include "pccore.h"
#include	"iocore.h"
#include	"sound/sound.h"
#include	"sound/beep.h"
#include	"sound/fmboard.h"
#include	"sound/soundrom.h"
#include	"cbus/mpu98ii.h"
#if defined(SUPPORT_SMPU98)
#include	"cbus/smpu98.h"
#endif
#endif

GocaineJCI JIT_CACHE_INFO[1048576];

#ifdef _ARM_
/*
push {lr}

---

0000: 00 B5
*/
BYTE jitstart[] = { 0x00,0xB5 };
/*
push.w {lr}
ldr r1,(testlabel+12)
ldr r0,(testlabel+16)
blx r1
nop
ldr r1,(testlabel)
ldr r0,(testlabel+20)
blx r1
nop
ldr r2,(testlabel+8)
ldr r0,(testlabel+24)
ldr r1,(testlabel+28)
blx r2
nop
pop {lr}
mov r15,r0
nop

testlabel:
0x00000000
0x00000000
0x00000000
0x00000000
0x00000000
0x00000000
0x00000000

---

0000:4D F8 04 ED
0004:DF F8 38 10
0008:DF F8 38 00
000c:88 47
000e:00 BF
0010:DF F8 20 10
0014:DF F8 30 00
0018:88 47
001a:00 BF
001c:DF F8 1C 20
0020:DF F8 28 00
0024:DF F8 28 10
0028:90 47
002a:00 BF
002c:5D F8 04 EB
0030:87 46
0032:00 BF

0034:00 00 00 00(pointer to armed x86 inst for emulation)
0038:00 00 00 00(lr for backup)
003c:00 00 00 00(get next jited inst)
0040:00 00 00 00(function for add eip)
0044:00 00 00 00(int for added to x86 eip)
0048:00 00 00 00(x86repinstid)
004c:00 00 00 00(baseaddr for phy addr)
0050:00 00 00 00(baseaddr for virtual addr)

*/
BYTE jittemplate[] = { 0x4D,0xF8,0x04,0xED,0xDF,0xF8,0x38,0x10,0xDF,0xF8,0x38,0x00,0x88,0x47,0x00,0xBF,0xDF,0xF8,0x20,0x10,0xDF,0xF8,0x30,0x00,0x88,0x47,0x00,0xBF,0xDF,0xF8,0x1C,0x20,0xDF,0xF8,0x28,0x00,0xDF,0xF8,0x28,0x10,0x90,0x47,0x00,0xBF,0x5D,0xF8,0x04,0xEB,0x87,0x46,0x00,0xBF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
/*
mov pc,lr

---

0000: F7 46
*/
BYTE jitend[] = { 0xF7,0x46 };
#else
#ifdef _M_IX86
/*
mov eax,[0x12345678]
mov [0x12345678],eax
add eax,0x12345678
mov [0x12345678],eax
push 0x12345678
mov eax,0
call eax
add esp,4
push 0x12345678
push 0x12345678
mov eax,0
call eax
add esp,8
jmp eax

---

0000:A1 78 56 34 12
0005:A3 78 56 34 12
000a:05 78 56 34 12(int for added to x86 eip)(function for add eip)
000f:A3 78 56 34 12
0014:68 78 56 34 12(x86repinstid)
0019:B8 00 00 00 00(pointer to nested x86 inst for emulation)
001e:FF D0
0020:83 C4 04
0023:68 78 56 34 12(baseaddr for virtual addr)
0028:68 78 56 34 12(baseaddr for phy addr)
002d:B8 00 00 00 00(get next jited inst)
0032:FF D0
0034:83 C4 08
0037:FF E0
*/
BYTE jittemplate[] = { 0xA1,0x78,0x56,0x34,0x12,0xA3,0x78,0x56,0x34,0x12,0x05,0x78,0x56,0x34,0x12,0xA3,0x78,0x56,0x34,0x12,0x68,0x78,0x56,0x34,0x12,0xB8,0x00,0x00,0x00,0x00,0xFF,0xD0,0x83,0xC4,0x04,0x68,0x78,0x56,0x34,0x12,0x68,0x78,0x56,0x34,0x12,0xB8,0x00,0x00,0x00,0x00,0xFF,0xD0,0x83,0xC4,0x08,0xFF,0xE0};
/*
ret

---

0000:C3
*/
BYTE jitend[] = { 0xC3 };
#else
BYTE jitend[] = { 0x00 };
BYTE jittemplate[] = { 0x00 };
#endif
#endif


UINT32 GetNowEIP4ACC(UINT32 offset) {
	descriptor_t* sdp;
	UINT32 addr;
	sdp = &CPU_CS_DESC;
	addr = sdp->u.seg.segbase + offset;
	return addr;
}

extern void genjitcode();

bool flag48c10 = false;

void setallocforjitret() {
	DWORD tmp;
	VirtualProtect(jitend, sizeof(jitend), 0x40, &tmp);
	VirtualProtect(jittemplate, sizeof(jittemplate), 0x40, &tmp);
}

UINT32 preveip4jitlpinst = 0;

void ADDEIPAddr(int prm_0){
	//printf("EIP:%08X\n", CPU_EIP);
	//if (flag48c10 == true) { printf("EIP:%08X = %02X\nESP:%08X\nprm_0:%08X\nCPU_INST_REPUSE:%02X\n", CPU_EIP,(*(BYTE*)(CPU_EIP)),CPU_ESP,prm_0, CPU_INST_REPUSE); }
#if 0
	if (CPU_INST_REPUSE/* && preveip4jitlpinst == 0*/) {
		preveip4jitlpinst = GetNowEIP4ACC(CPU_EIP);
	}
	else {
		preveip4jitlpinst = 0;
	CPU_PREV_EIP = CPU_EIP;
	CPU_EIP += prm_0;
	}
#endif
	preveip4jitlpinst = GetNowEIP4ACC(CPU_EIP);
	CPU_PREV_EIP = CPU_EIP;
	CPU_EIP += prm_0;
}

void* emalloc(size_t sizeofcode){
	//void* ret = malloc(sizeofcode);
	void* ret = VirtualAlloc(0, sizeofcode, 0x3000, PAGE_EXECUTE_READWRITE);
	//DWORD tmp;
	//if (ret != 0) { VirtualProtect(ret, sizeofcode, PAGE_EXECUTE_READWRITE, &tmp); }
	//printf("%08X\n", ret);
	return ret;
}

UINT32 GetSameInstAddr(UINT32 prm_0) {
	return ((sizeof(jittemplate) * (prm_0 & 0xFFF)) + ((CPU_INST_OP32) ? (UINT32)JIT_CACHE_INFO[(prm_0 >> 12) & 0xFFFFF].jit32 : (UINT32)JIT_CACHE_INFO[(prm_0 >> 12) & 0xFFFFF].jit16));
}

UINT32 GetNextNtCLAddrAR(UINT32 prm_0, UINT32 prm_1) {
	if (!(insttable_info[cpu_codefetch((prm_0 & 0xFFFFF000) + (CPU_EIP & 0xFFF))] & INST_PREFIX)) {
		CPU_STATSAVE.cpu_inst = CPU_STATSAVE.cpu_inst_default;
	}
	return (UINT32)(&jitend);
}

UINT32 GetNextNtCLAddr(UINT32 prm_0, UINT32 prm_1) {
	/*printf("EIP:%08X\n", CPU_EIP);
	printf("PADDR:%08X\n",prm_0);
	printf("VADDR:%08X\n",prm_1);*/
	CPU_STATSAVE.cpu_inst = CPU_STATSAVE.cpu_inst_default;
	if ((prm_1 & 0xFFFFF000) == (GetNowEIP4ACC(CPU_EIP) & 0xFFFFF000)) {
		return ((sizeof(jittemplate) * (GetNowEIP4ACC(CPU_EIP) & 0xFFF)) + ((CPU_INST_OP32) ? (UINT32)JIT_CACHE_INFO[(prm_0>>12)&0xFFFFF].jit32 : (UINT32)JIT_CACHE_INFO[(prm_0 >> 12) & 0xFFFFF].jit16));
	} else {
		return (UINT32)(&jitend);
regetretpt:
		UINT32 retpt = (CPU_INST_OP32) ? ((sizeof(jittemplate) * (GetNowEIP4ACC(CPU_EIP) & 0xFFF)) + ((UINT32)JIT_CACHE_INFO[((laddr_to_paddr(GetNowEIP4ACC(CPU_EIP) & 0xFFFFF000, CPU_PAGE_READ_CODE | CPU_STAT_USER_MODE) >> 12) & 0xFFFFF)].jit32)) : ((sizeof(jittemplate) * (CPU_EIP & 0xFFF)) + ((UINT32)JIT_CACHE_INFO[((laddr_to_paddr(GetNowEIP4ACC(CPU_EIP) & 0xFFFFF000, CPU_PAGE_READ_CODE | CPU_STAT_USER_MODE) >> 12) & 0xFFFFF)].jit16));
		if (retpt == 0) { genjitcode(); goto regetretpt; }
		return (UINT32)(&retpt);
	}
}

UINT32 GetNextNtCLAddrNCKZF(UINT32 prm_0, UINT32 prm_1) {
	if (CPU_INST_REPUSE) { if (CPU_CX != 0) { if (--CPU_CX == 0) { CPU_INST_REPUSE = 0; } else { return GetSameInstAddr((prm_0 & 0xFFFFF000) | (preveip4jitlpinst & 0xFFF)); } } else { CPU_INST_REPUSE = 0; } }
	return GetNextNtCLAddr(prm_0, prm_1);
}
UINT32 GetNextNtCLAddrNF2(UINT32 prm_0, UINT32 prm_1) {
	if (CPU_INST_REPUSE) { if (CPU_CX != 0) { if (CPU_INST_REPUSE != 0xf2) { if (--CPU_CX != 0 || CC_NZ) { CPU_INST_REPUSE = 0; } else { return GetSameInstAddr((prm_0&0xFFFFF000)|(preveip4jitlpinst&0xFFF)); } } else { if (--CPU_CX == 0 || CC_Z) { CPU_INST_REPUSE = 0; } else { return GetSameInstAddr((prm_0&0xFFFFF000)|(preveip4jitlpinst&0xFFF)); } } } else { CPU_INST_REPUSE = 0; } }
	return GetNextNtCLAddr(prm_0, prm_1);
}


extern UINT32 CPU_PREV_PC;
extern UINT16 CPU_PREV_CS;
extern UINT32 codefetch_address;

typedef void typeofrunjitedopcodes();

void
exec_1step_internal(void)
{
	int prefix;
	UINT32 op;

#if defined(USE_DEBUGGER)
	CPU_PREV_CS = CPU_CS;
#endif
		CPU_PREV_EIP = CPU_EIP;
		CPU_STATSAVE.cpu_inst = CPU_STATSAVE.cpu_inst_default;

#if defined(ENABLE_TRAP)
	steptrap(CPU_CS, CPU_EIP);
#endif

#if defined(IA32_INSTRUCTION_TRACE)
	ctx[ctx_index].regs = CPU_STATSAVE.cpu_regs;
	if (cpu_inst_trace) {
		disasm_context_t* d = &ctx[ctx_index].disasm;
		UINT32 eip = CPU_EIP;
		int rv;

		rv = disasm(&eip, d);
		if (rv == 0) {
			char buf[256];
			char tmp[32];
			int len = d->nopbytes > 8 ? 8 : d->nopbytes;
			int i;

			buf[0] = '\0';
			for (i = 0; i < len; i++) {
				snprintf(tmp, sizeof(tmp), "%02x ", d->opbyte[i]);
				milstr_ncat(buf, tmp, sizeof(buf));
			}
			for (; i < 8; i++) {
				milstr_ncat(buf, "   ", sizeof(buf));
			}
			VERBOSE(("%04x:%08x: %s%s", CPU_CS, CPU_EIP, buf, d->str));

			buf[0] = '\0';
			for (; i < d->nopbytes; i++) {
				snprintf(tmp, sizeof(tmp), "%02x ", d->opbyte[i]);
				milstr_ncat(buf, tmp, sizeof(buf));
				if ((i % 8) == 7) {
					VERBOSE(("             : %s", buf));
					buf[0] = '\0';
				}
			}
			if ((i % 8) != 0) {
				VERBOSE(("             : %s", buf));
			}
		}
	}
	ctx[ctx_index].opbytes = 0;
#endif

	for (prefix = 0; prefix < MAX_PREFIX; prefix++) {
		GET_PCBYTE(op);
		if (prefix == 0) {
			CPU_PREV_PC = codefetch_address;
#if defined(USE_DEBUGGER)
			add_cpu_trace(CPU_PREV_PC, CPU_PREV_CS, CPU_PREV_EIP);
#endif
		}
#if defined(IA32_INSTRUCTION_TRACE)
		ctx[ctx_index].op[prefix] = op;
		ctx[ctx_index].opbytes++;
#endif

		/* prefix */
		if (insttable_info[op] & INST_PREFIX) {
			(*insttable_1byte[0][op])();
			continue;
		}
		break;
}
	if (prefix == MAX_PREFIX) {
		EXCEPTION(UD_EXCEPTION, 0);
	}

#if defined(IA32_INSTRUCTION_TRACE)
	if (op == 0x0f) {
		BYTE op2;
		op2 = cpu_codefetch(CPU_EIP);
		ctx[ctx_index].op[prefix + 1] = op2;
		ctx[ctx_index].opbytes++;
	}
	ctx_index = (ctx_index + 1) % NELEMENTS(ctx);
#endif

	/* normal / rep, but not use */
	if (!(insttable_info[op] & INST_STRING) || !CPU_INST_REPUSE) {
#if defined(DEBUG)
		cpu_debug_rep_cont = 0;
#endif
		(*insttable_1byte[CPU_INST_OP32][op])();
		return;
	}

	/* rep */
	CPU_WORKCLOCK(5);
#if defined(DEBUG)
	if (!cpu_debug_rep_cont) {
		cpu_debug_rep_cont = 1;
		cpu_debug_rep_regs = CPU_STATSAVE.cpu_regs;
	}
#endif
	if (!CPU_INST_AS32) {
		if (CPU_CX != 0) {
			if (!(insttable_info[op] & REP_CHECKZF)) {
				if(insttable_1byte_repfunc[CPU_INST_OP32][op]){
					(*insttable_1byte_repfunc[CPU_INST_OP32][op])(0);
				}else{
				/* rep */
				for (;;) {
					(*insttable_1byte[CPU_INST_OP32][op])();
					if (--CPU_CX == 0) {
#if defined(DEBUG)
						cpu_debug_rep_cont = 0;
#endif
						break;
					}
					if (CPU_REMCLOCK <= 0) {
						CPU_EIP = CPU_PREV_EIP;
						break;
					}
				}
				}
			}
			else if (CPU_INST_REPUSE != 0xf2) {
				if(insttable_1byte_repfunc[CPU_INST_OP32][op]){
					(*insttable_1byte_repfunc[CPU_INST_OP32][op])(1);
				}else{
				/* repe */
				for (;;) {
					(*insttable_1byte[CPU_INST_OP32][op])();
					if (--CPU_CX == 0 || CC_NZ) {
#if defined(DEBUG)
						cpu_debug_rep_cont = 0;
#endif
						break;
					}
					if (CPU_REMCLOCK <= 0) {
						CPU_EIP = CPU_PREV_EIP;
						break;
					}
				}
				}
			}
			else {
				if(insttable_1byte_repfunc[CPU_INST_OP32][op]){
					(*insttable_1byte_repfunc[CPU_INST_OP32][op])(2);
				}else{
				/* repne */
				for (;;) {
					(*insttable_1byte[CPU_INST_OP32][op])();
					if (--CPU_CX == 0 || CC_Z) {
#if defined(DEBUG)
						cpu_debug_rep_cont = 0;
#endif
						break;
					}
					if (CPU_REMCLOCK <= 0) {
						CPU_EIP = CPU_PREV_EIP;
						break;
					}
				}
				}
			}
		}
	}
	else {
		if (CPU_ECX != 0) {
			if (!(insttable_info[op] & REP_CHECKZF)) {
				if(insttable_1byte_repfunc[CPU_INST_OP32][op]){
					(*insttable_1byte_repfunc[CPU_INST_OP32][op])(0);
				}else{
				/* rep */
				for (;;) {
					(*insttable_1byte[CPU_INST_OP32][op])();
					if (--CPU_ECX == 0) {
#if defined(DEBUG)
						cpu_debug_rep_cont = 0;
#endif
						break;
					}
					if (CPU_REMCLOCK <= 0) {
						CPU_EIP = CPU_PREV_EIP;
						break;
					}
				}
				}
			}
			else if (CPU_INST_REPUSE != 0xf2) {
				if(insttable_1byte_repfunc[CPU_INST_OP32][op]){
					(*insttable_1byte_repfunc[CPU_INST_OP32][op])(1);
				}else{
				/* repe */
				for (;;) {
					(*insttable_1byte[CPU_INST_OP32][op])();
					if (--CPU_ECX == 0 || CC_NZ) {
#if defined(DEBUG)
						cpu_debug_rep_cont = 0;
#endif
						break;
					}
					if (CPU_REMCLOCK <= 0) {
						CPU_EIP = CPU_PREV_EIP;
						break;
					}
				}
				}
			}
			else {
				if(insttable_1byte_repfunc[CPU_INST_OP32][op]){
					(*insttable_1byte_repfunc[CPU_INST_OP32][op])(2);
				}else{
				/* repne */
				for (;;) {
					(*insttable_1byte[CPU_INST_OP32][op])();
					if (--CPU_ECX == 0 || CC_Z) {
#if defined(DEBUG)
						cpu_debug_rep_cont = 0;
#endif
						break;
					}
					if (CPU_REMCLOCK <= 0) {
						CPU_EIP = CPU_PREV_EIP;
						break;
					}
				}
				}
			}
		}
	}
}

UINT32 getmovrr32(int prm_0, int prm_1) { return (0x2A0003E0 | ((prm_0 & 0x1f) << 24) | ((prm_1 & 0x1f) << 8)); }

void genjitcode() {
	int prefix;
	UINT32 op=0;
	int opold=-1;
#ifdef _ARM64_
	BYTE* jittmp = (BYTE*)malloc(4096*8+4096);
	UINT32 jittmppls, jittmpplsold;
	jittmppls = 0;
	UINT64 eiptmpp = laddr_to_paddr(GetNowEIP4ACC(CPU_EIP) & 0xFFFFF000, CPU_PAGE_READ_CODE | CPU_STAT_USER_MODE);
	UINT64 eiptmpl = CPU_EIP & 0xFFFFF000;
	for (int cnt4translate = 0; cnt4translate < 4096; cnt4translate++) {
		*(DWORD*)(jittmp + jittmppls + 4096) = 0; jittmppls += 4;
		jittmpplsold = jittmppls;
	}
	if (CPU_INST_OP32) { JIT_CACHE_INFO[(((*(DWORD*)(jittemplate + 0x24)) >> 12) & 0x000FFFFF)].jit32 = jittmp; }
	else { JIT_CACHE_INFO[(((*(DWORD*)(jittemplate + 0x24)) >> 12) & 0x000FFFFF)].jit16 = jittmp; }

	JIT_CACHE_INFO[(((*(DWORD*)(jittemplate + 0x24)) >> 12) & 0x000FFFFF)].jitinfo |= (1 << (CPU_INST_OP32 ? 1 : 0));
#else
	BYTE* jittmp = (BYTE*)emalloc(sizeof(jittemplate) * 4096);
#ifdef _ARM_
	*(DWORD*)(jittemplate+0x4c) = laddr_to_paddr(GetNowEIP4ACC(CPU_EIP) & 0xFFFFF000, CPU_PAGE_READ_CODE | CPU_STAT_USER_MODE);
	*(DWORD*)(jittemplate+0x50) = CPU_EIP & 0xFFFFF000;
	for (int cnt4translate = 0; cnt4translate < 4096; cnt4translate++) {
		*(DWORD*)(jittemplate+0x40) = (DWORD)(&ADDEIPAddr) | 1;
		*(DWORD*)(jittemplate+0x3c) = (DWORD)(&GetNextNtCLAddr) | 1;
		*(DWORD*)(jittemplate + 0x48) = 0;
		*(DWORD*)(jittemplate + 0x44) = 1;
		op = cpu_codefetch((*(DWORD*)(jittemplate + 0x50)) + cnt4translate);
		if (op == 0x0f) {
			op = cpu_codefetch((*(DWORD*)(jittemplate + 0x50)) + cnt4translate + 1);
			*(DWORD*)(jittemplate + 0x44) = 2;
			*(DWORD*)(jittemplate + 0x34) = (DWORD)insttable_2byte[CPU_INST_OP32][op];
		} else if (insttable_info[op] & INST_PREFIX) {
			*(DWORD*)(jittemplate + 0x44) = 0;
			*(DWORD*)(jittemplate + 0x34) = (DWORD)(&exec_1step_internal);
		} else {
			*(DWORD*)(jittemplate+ 0x34) = (DWORD)insttable_1byte[CPU_INST_OP32][op];
			//if (op == 0xc3 || op == 0xc2) { *(DWORD*)(jittemplate + 0x3c) = (DWORD)(&GetNextNtCLAddrAR); }
		}
		memcpy(jittmp + (cnt4translate * sizeof(jittemplate)), jittemplate, sizeof(jittemplate));
		if (cnt4translate >= 4096) { break; }
	}
	jittmp++;
	if (CPU_INST_OP32) { JIT_CACHE_INFO[(((*(DWORD*)(jittemplate+0x4c)) >> 12) & 0x000FFFFF)].jit32 = jittmp; }
	else { JIT_CACHE_INFO[(((*(DWORD*)(jittemplate+0x4c)) >> 12) & 0x000FFFFF)].jit16 = jittmp; }
	jittmp--;

	JIT_CACHE_INFO[(((*(DWORD*)(jittemplate+0x4c)) >> 12) & 0x000FFFFF)].jitinfo |= (1 << (CPU_INST_OP32 ? 1 : 0));
#else
#ifdef _M_IX86
	*(DWORD*)(jittemplate+0x24+5) = laddr_to_paddr(GetNowEIP4ACC(CPU_EIP) & 0xFFFFF000, CPU_PAGE_READ_CODE | CPU_STAT_USER_MODE);
	*(DWORD*)(jittemplate+0x1f+5) = CPU_EIP & 0xFFFFF000;
	for (int cnt4translate = 0; cnt4translate < 4096; cnt4translate++) {
		*(DWORD*)(jittemplate+0x10+5) = 0;
		*(DWORD*)(jittemplate+0x1) = (DWORD)(&CPU_EIP);
		*(DWORD*)(jittemplate+0x6) = (DWORD)(&CPU_PREV_EIP);
		*(DWORD*)(jittemplate+0xb+5) = (DWORD)(&CPU_EIP);
		*(DWORD*)(jittemplate+0x29+5) = (DWORD)(&GetNextNtCLAddr);
		*(DWORD*)(jittemplate + 0x6+5) = 1;

		op = cpu_codefetch((*(DWORD*)(jittemplate + 0x1f + 5)) + cnt4translate);
		if (op == 0x0f) {
			op = cpu_codefetch((*(DWORD*)(jittemplate + 0x1f + 5)) + cnt4translate + 1);
			*(DWORD*)(jittemplate + 0x6 + 5) = 2;
			*(DWORD*)(jittemplate + 0x15 + 5) = (DWORD)insttable_2byte[CPU_INST_OP32][op];
		} else if (insttable_info[op] & INST_PREFIX) {
			*(DWORD*)(jittemplate + 0x6 + 5) = 0;
			*(DWORD*)(jittemplate + 0x15 + 5) = (DWORD)(&exec_1step_internal);
		} else {
			*(DWORD*)(jittemplate+0x15 + 5) = (DWORD)insttable_1byte[CPU_INST_OP32][op];
			//if (op == 0xc3 || op == 0xc2) { *(DWORD*)(jittemplate + 0x29) = (DWORD)(&GetNextNtCLAddrAR); }
		}
		memcpy(jittmp + (cnt4translate * sizeof(jittemplate)), jittemplate, sizeof(jittemplate));
		if (cnt4translate >= 4096) { break; }
	}
	if (CPU_INST_OP32) { JIT_CACHE_INFO[(((*(DWORD*)(jittemplate+0x24)) >> 12) & 0x000FFFFF)].jit32 = jittmp; }
	else { JIT_CACHE_INFO[(((*(DWORD*)(jittemplate+0x24)) >> 12) & 0x000FFFFF)].jit16 = jittmp; }

	JIT_CACHE_INFO[(((*(DWORD*)(jittemplate+0x24)) >> 12) & 0x000FFFFF)].jitinfo |= (1 << (CPU_INST_OP32 ? 1 : 0));
#endif
#endif
#endif
	FlushInstructionCache(GetCurrentProcess(), jittmp, sizeof(jittemplate) * 4096);
}

bool execjitfirsttime = false;

DWORD addrbaks = 0;

void execjit() {
	if (execjitfirsttime == false) { setallocforjitret(); execjitfirsttime = true; }
	/*if ((CPU_INST_OP32 ? JIT_CACHE_INFO[((GetNowEIP4ACC(CPU_EIP) >> 12) & 0x000FFFFF)].jit32lp : JIT_CACHE_INFO[((GetNowEIP4ACC(CPU_EIP) >> 12) & 0x000FFFFF)].jit16lp) <= 50) {
		//printf("Looping:%d\n", (CPU_INST_OP32 ? JIT_CACHE_INFO[((GetNowEIP4ACC(CPU_EIP) >> 12) & 0x000FFFFF)].jit32lp : JIT_CACHE_INFO[((GetNowEIP4ACC(CPU_EIP) >> 12) & 0x000FFFFF)].jit16lp));
		if (addrbaks != (GetNowEIP4ACC(CPU_EIP) &0xFFFFF000)) { addrbaks = (GetNowEIP4ACC(CPU_EIP) & 0xFFFFF000); if (CPU_INST_OP32) { JIT_CACHE_INFO[((GetNowEIP4ACC(CPU_EIP) >> 12) & 0x000FFFFF)].jit32lp ++; } else { JIT_CACHE_INFO[((GetNowEIP4ACC(CPU_EIP) >> 12) & 0x000FFFFF)].jit16lp ++; } }
		//while (addrbaks == (GetNowEIP4ACC(CPU_EIP) & 0xFFFFF000)) {
			exec_1step();
		//}
	} else {*/
		//printf("EIP:%08X\n", CPU_EIP);
		//if ((GetNowEIP4ACC(CPU_EIP) &0xFFFF)==0x8c10) { flag48c10 = true; }else{ flag48c10 = false; }
		if (!(JIT_CACHE_INFO[((GetNowEIP4ACC(CPU_EIP) >> 12) & 0x000FFFFF)].jitinfo & (1 << (CPU_INST_OP32 ? 1 : 0)))) {
			genjitcode();
		}
		if (!(insttable_info[cpu_codefetch(laddr_to_paddr(CPU_EIP, CPU_PAGE_READ_CODE | CPU_STAT_USER_MODE))] & INST_PREFIX)) {
			CPU_STATSAVE.cpu_inst = CPU_STATSAVE.cpu_inst_default;
		}
		if (CPU_INST_OP32) {
			((typeofrunjitedopcodes*)(((UINT64)JIT_CACHE_INFO[((GetNowEIP4ACC(CPU_EIP) >> 12) & 0x000FFFFF)].jit32) + ((GetNowEIP4ACC(CPU_EIP) & 0xFFF) * sizeof(jittemplate))))();
		}
		else { ((typeofrunjitedopcodes*)(((UINT64)JIT_CACHE_INFO[((GetNowEIP4ACC(CPU_EIP) >> 12) & 0x000FFFFF)].jit16) + ((GetNowEIP4ACC(CPU_EIP) & 0xFFF) * sizeof(jittemplate))))(); }
	//}
	//printf("EIP:%08X\n", CPU_EIP);
}

