#ifndef IA32_CPU_JIT_H__
#define IA32_CPU_JIT_H__
typedef struct
{
	UINT8 jitinfo;
	void* jit16;
	void* jit32;
	UINT8 jit16lp;
	UINT8 jit32lp;
} GocaineJCI;

extern GocaineJCI JIT_CACHE_INFO[1048576];

void execjit();

#endif
