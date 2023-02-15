/*
* Tencent is pleased to support the open source community by making Libco available.

* Copyright (C) 2014 THL A29 Limited, a Tencent company. All rights reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License"); 
* you may not use this file except in compliance with the License. 
* You may obtain a copy of the License at
*
*	http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, 
* software distributed under the License is distributed on an "AS IS" BASIS, 
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
* See the License for the specific language governing permissions and 
* limitations under the License.
*/

#include "co_routine.h"
#include "co_routine_inner.h"
#include "co_epoll.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <map>

#include <poll.h>
#include <sys/time.h>
#include <errno.h>

#include <assert.h>

#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <limits.h>

extern "C"
{
	extern void coctx_swap( coctx_t *,coctx_t* ) asm("coctx_swap");
};
using namespace std;
stCoRoutine_t *GetCurrCo( stCoRoutineEnv_t *env );
struct stCoEpoll_t;

// 协程环境结构体
// 协程运行的环境，每个线程创建一个，当前线程所有协程共享
struct stCoRoutineEnv_t
{
	// 按照调用关系记录当前协程调用栈，最多128层调用
	// 最后一个协程pCallStack[iCallStackSize-1]为当前执行的协程
	// 而pCallStack[iCallStackSize-2]为当前协程的父协程
	stCoRoutine_t *pCallStack[ 128 ];
	// 当前调用栈长度
	int iCallStackSize;
	// epoll协程调度器
	stCoEpoll_t *pEpoll;

	// 共享栈模式下使用
	//for copy stack log lastco and nextco
	// 待执行的协程
	stCoRoutine_t* pending_co;
	// 正在执行的协程(马上被切换)
	stCoRoutine_t* occupy_co;
};
//int socket(int domain, int type, int protocol);
void co_log_err( const char *fmt,... )
{
}


#if defined( __LIBCO_RDTSCP__) 
static unsigned long long counter(void)
{
	register uint32_t lo, hi;
	register unsigned long long o;
	__asm__ __volatile__ (
			"rdtscp" : "=a"(lo), "=d"(hi)::"%rcx"
			);
	o = hi;
	o <<= 32;
	return (o | lo);

}
static unsigned long long getCpuKhz()
{
	FILE *fp = fopen("/proc/cpuinfo","r");
	if(!fp) return 1;
	char buf[4096] = {0};
	fread(buf,1,sizeof(buf),fp);
	fclose(fp);

	char *lp = strstr(buf,"cpu MHz");
	if(!lp) return 1;
	lp += strlen("cpu MHz");
	while(*lp == ' ' || *lp == '\t' || *lp == ':')
	{
		++lp;
	}

	double mhz = atof(lp);
	unsigned long long u = (unsigned long long)(mhz * 1000);
	return u;
}
#endif

static unsigned long long GetTickMS()
{
#if defined( __LIBCO_RDTSCP__) 
	static uint32_t khz = getCpuKhz();
	return counter() / khz;
#else
	struct timeval now = { 0 };
	gettimeofday( &now,NULL );
	unsigned long long u = now.tv_sec;
	u *= 1000;
	u += now.tv_usec / 1000;
	return u;
#endif
}

/* no longer use
static pid_t GetPid()
{
    static __thread pid_t pid = 0;
    static __thread pid_t tid = 0;
    if( !pid || !tid || pid != getpid() )
    {
        pid = getpid();
#if defined( __APPLE__ )
		tid = syscall( SYS_gettid );
		if( -1 == (long)tid )
		{
			tid = pid;
		}
#elif defined( __FreeBSD__ )
		syscall(SYS_thr_self, &tid);
		if( tid < 0 )
		{
			tid = pid;
		}
#else 
        tid = syscall( __NR_gettid );
#endif

    }
    return tid;

}
static pid_t GetPid()
{
	char **p = (char**)pthread_self();
	return p ? *(pid_t*)(p + 18) : getpid();
}
*/

// 将ap节点从其对应的双向链表上移除
template <class T,class TLink>
void RemoveFromLink(T *ap)
{
	// 获取ap节点对应的链表
	TLink *lst = ap->pLink;
	if(!lst) return ;
	assert( lst->head && lst->tail );

	if( ap == lst->head )
	{
		lst->head = ap->pNext;
		if(lst->head)
		{
			lst->head->pPrev = NULL;
		}
	}
	else
	{
		if(ap->pPrev)
		{
			ap->pPrev->pNext = ap->pNext;
		}
	}

	if( ap == lst->tail )
	{
		lst->tail = ap->pPrev;
		if(lst->tail)
		{
			lst->tail->pNext = NULL;
		}
	}
	else
	{
		ap->pNext->pPrev = ap->pPrev;
	}

	ap->pPrev = ap->pNext = NULL;
	ap->pLink = NULL;
}

// 将ap节点加入双向链表apLink的末尾
template <class TNode,class TLink>
void inline AddTail(TLink*apLink,TNode *ap)
{
	if( ap->pLink )
	{
		return ;
	}
	if(apLink->tail)
	{
		apLink->tail->pNext = (TNode*)ap;
		ap->pNext = NULL;
		ap->pPrev = apLink->tail;
		apLink->tail = ap;
	}
	else
	{
		apLink->head = apLink->tail = ap;
		ap->pNext = ap->pPrev = NULL;
	}
	ap->pLink = apLink;
}

// 弹出双向链表apLink的头节点
template <class TNode,class TLink>
void inline PopHead( TLink*apLink )
{
	if( !apLink->head ) 
	{
		return ;
	}
	TNode *lp = apLink->head;
	if( apLink->head == apLink->tail )
	{
		apLink->head = apLink->tail = NULL;
	}
	else
	{
		apLink->head = apLink->head->pNext;
	}

	lp->pPrev = lp->pNext = NULL;
	lp->pLink = NULL;

	if( apLink->head )
	{
		apLink->head->pPrev = NULL;
	}
}

// 将apOther链表的节点都添加至apLink的末尾
template <class TNode,class TLink>
void inline Join( TLink*apLink,TLink *apOther )
{
	//printf("apOther %p\n",apOther);
	if( !apOther->head )
	{
		return ;
	}
	TNode *lp = apOther->head;
	while( lp )
	{
		lp->pLink = apLink;
		lp = lp->pNext;
	}
	lp = apOther->head;
	if(apLink->tail)
	{
		apLink->tail->pNext = (TNode*)lp;
		lp->pPrev = apLink->tail;
		apLink->tail = apOther->tail;
	}
	else
	{
		apLink->head = apOther->head;
		apLink->tail = apOther->tail;
	}

	apOther->head = apOther->tail = NULL;
}

/////////////////for copy stack //////////////////////////
// 创建指定大小的栈内存
stStackMem_t* co_alloc_stackmem(unsigned int stack_size)
{
	stStackMem_t* stack_mem = (stStackMem_t*)malloc(sizeof(stStackMem_t));
	stack_mem->occupy_co= NULL;
	stack_mem->stack_size = stack_size;
	stack_mem->stack_buffer = (char*)malloc(stack_size);
	stack_mem->stack_bp = stack_mem->stack_buffer + stack_size;
	return stack_mem;
}

// 创建count个指定大小的共享栈
stShareStack_t* co_alloc_sharestack(int count, int stack_size)
{
	stShareStack_t* share_stack = (stShareStack_t*)malloc(sizeof(stShareStack_t));
	share_stack->alloc_idx = 0;
	share_stack->stack_size = stack_size;

	//alloc stack array
	share_stack->count = count;
	stStackMem_t** stack_array = (stStackMem_t**)calloc(count, sizeof(stStackMem_t*));
	for (int i = 0; i < count; i++)
	{
		stack_array[i] = co_alloc_stackmem(stack_size);
	}
	share_stack->stack_array = stack_array;
	return share_stack;
}

// 从共享栈中获取一个栈内存(轮询)
static stStackMem_t* co_get_stackmem(stShareStack_t* share_stack)
{
	if (!share_stack)
	{
		return NULL;
	}
	int idx = share_stack->alloc_idx % share_stack->count;
	share_stack->alloc_idx++;

	return share_stack->stack_array[idx];
}


// ----------------------------------------------------------------------------
struct stTimeoutItemLink_t;
struct stTimeoutItem_t;
// 进一步封装的epoll上下文信息
struct stCoEpoll_t
{
	// epoll对应的id
	int iEpollFd;
	static const int _EPOLL_SIZE = 1024 * 10;

	// 超时管理器
	struct stTimeout_t *pTimeout;

	// 当前已超时事件列表
	struct stTimeoutItemLink_t *pstTimeoutList;

	// 当前待处理(被激活)事件列表
	struct stTimeoutItemLink_t *pstActiveList;

	// epoll结果相关信息
	co_epoll_res *result; 

};
typedef void (*OnPreparePfn_t)( stTimeoutItem_t *,struct epoll_event &ev, stTimeoutItemLink_t *active );
typedef void (*OnProcessPfn_t)( stTimeoutItem_t *);
// 超时(双向)链表中的各个节点
struct stTimeoutItem_t
{
	// @deprecated 未使用
	enum
	{
		eMaxTimeout = 40 * 1000 //40s
	};
	// 前一个节点
	stTimeoutItem_t *pPrev;
	// 后一个节点
	stTimeoutItem_t *pNext;
	// 当前节点对应的链表
	stTimeoutItemLink_t *pLink;

	// 当前事件的失效时间
	unsigned long long ullExpireTime;

	// 注册的自定义预处理函数，在eventloop中调用，用于将时间从时间管理器移除等工作
	OnPreparePfn_t pfnPrepare;
	// 注册的自定义处理函数，在eventloop中调用，内部调用resume，将执行权从epoll_loop主循环交回注册该事件的业务协程，用于处理该事件
	OnProcessPfn_t pfnProcess;

	// pfnPrepare和pfnProcess函数的的输入参数，为一个协程
	void *pArg; // routine 
	// 是否已经超时
	bool bTimeout;
};

// 超时链表
struct stTimeoutItemLink_t
{
	stTimeoutItem_t *head;
	stTimeoutItem_t *tail;

};

// 超时管理器，使用时间轮实现
struct stTimeout_t
{
	// 超时事件链表，大小为iItemSize，每一项代表1ms，其对应一个链表，该链表中所有的事件都是当前事件点失效的事件
	stTimeoutItemLink_t *pItems;
	// 默认大小为60 * 1000
	int iItemSize;

	// 超时管理器当前已处理过的最新的时间
	unsigned long long ullStart;
	// 目前已处理的最新的时间对应pItems上的索引
	long long llStartIdx;
};

// 创建一个超时管理器
stTimeout_t *AllocTimeout( int iSize )
{
	stTimeout_t *lp = (stTimeout_t*)calloc( 1,sizeof(stTimeout_t) );	

	lp->iItemSize = iSize;
	lp->pItems = (stTimeoutItemLink_t*)calloc( 1,sizeof(stTimeoutItemLink_t) * lp->iItemSize );

	lp->ullStart = GetTickMS();
	lp->llStartIdx = 0;

	return lp;
}

// 释放超时管理器资源
void FreeTimeout( stTimeout_t *apTimeout )
{
	free( apTimeout->pItems );
	free ( apTimeout );
}

// 向超时管理器中添加一个事件
int AddTimeout( stTimeout_t *apTimeout,stTimeoutItem_t *apItem ,unsigned long long allNow )
{
	if( apTimeout->ullStart == 0 )
	{
		apTimeout->ullStart = allNow;
		apTimeout->llStartIdx = 0;
	}
	if( allNow < apTimeout->ullStart )
	{
		co_log_err("CO_ERR: AddTimeout line %d allNow %llu apTimeout->ullStart %llu",
					__LINE__,allNow,apTimeout->ullStart);

		return __LINE__;
	}
	if( apItem->ullExpireTime < allNow )
	{
		co_log_err("CO_ERR: AddTimeout line %d apItem->ullExpireTime %llu allNow %llu apTimeout->ullStart %llu",
					__LINE__,apItem->ullExpireTime,allNow,apTimeout->ullStart);

		return __LINE__;
	}
	// 使用当前事件的超时时间 减去 超时管理器已经处理到的时间 得到当前超时管理器应放入的时间片分桶
	unsigned long long diff = apItem->ullExpireTime - apTimeout->ullStart;

	if( diff >= (unsigned long long)apTimeout->iItemSize )
	{
		diff = apTimeout->iItemSize - 1;
		co_log_err("CO_ERR: AddTimeout line %d diff %d",
					__LINE__,diff);

		//return __LINE__;
	}
	// 将当前事件加入对应失效时间分桶的链表末尾
	AddTail( apTimeout->pItems + ( apTimeout->llStartIdx + diff ) % apTimeout->iItemSize , apItem );

	return 0;
}

// 获取所有的超时事件
inline void TakeAllTimeout( stTimeout_t *apTimeout,unsigned long long allNow,stTimeoutItemLink_t *apResult )
{
	if( apTimeout->ullStart == 0 )
	{
		apTimeout->ullStart = allNow;
		apTimeout->llStartIdx = 0;
	}

	if( allNow < apTimeout->ullStart )
	{
		return ;
	}
	// 获取已经达到失效时间的时间轮的范围
	int cnt = allNow - apTimeout->ullStart + 1;
	if( cnt > apTimeout->iItemSize )
	{
		cnt = apTimeout->iItemSize;
	}
	if( cnt < 0 )
	{
		return;
	}
	// 从时间轮中取出对应的超时事件链表，将对应的事件放入apResult中
	for( int i = 0;i<cnt;i++)
	{
		int idx = ( apTimeout->llStartIdx + i) % apTimeout->iItemSize;
		// 将超时时间join到apResult上
		Join<stTimeoutItem_t,stTimeoutItemLink_t>( apResult,apTimeout->pItems + idx  );
	}
	// 更新时间轮的信息
	apTimeout->ullStart = allNow;
	apTimeout->llStartIdx += cnt - 1;
}

// 协程执行的任务函数，执行业务注册的函数pfn，并执行yield让出控制权
static int CoRoutineFunc( stCoRoutine_t *co,void * )
{
	if( co->pfn )
	{
		co->pfn( co->arg );
	}
	co->cEnd = 1;

	stCoRoutineEnv_t *env = co->env;

	co_yield_env( env );

	return 0;
}

// 根据指定参数，创建一个协程
struct stCoRoutine_t *co_create_env( stCoRoutineEnv_t * env, const stCoRoutineAttr_t* attr,
		pfn_co_routine_t pfn,void *arg )
{

	stCoRoutineAttr_t at;
	if( attr )
	{
		memcpy( &at,attr,sizeof(at) );
	}
	if( at.stack_size <= 0 )
	{
		at.stack_size = 128 * 1024;
	}
	else if( at.stack_size > 1024 * 1024 * 8 )
	{
		at.stack_size = 1024 * 1024 * 8;
	}

	// 保证栈大小为4kb的倍数
	if( at.stack_size & 0xFFF ) 
	{
		at.stack_size &= ~0xFFF;
		at.stack_size += 0x1000;
	}

	stCoRoutine_t *lp = (stCoRoutine_t*)malloc( sizeof(stCoRoutine_t) );
	
	memset( lp,0,(long)(sizeof(stCoRoutine_t))); 


	lp->env = env;
	lp->pfn = pfn;
	lp->arg = arg;

	stStackMem_t* stack_mem = NULL;
	if( at.share_stack )
	{
		stack_mem = co_get_stackmem( at.share_stack);
		at.stack_size = at.share_stack->stack_size;
	}
	else
	{
		stack_mem = co_alloc_stackmem(at.stack_size);
	}
	// 按照共享栈/独立栈的模式设置栈内存
	lp->stack_mem = stack_mem;

	// 将协程的寄存器信息绑定至协程栈中
	lp->ctx.ss_sp = stack_mem->stack_buffer;
	lp->ctx.ss_size = at.stack_size;

	lp->cStart = 0;
	lp->cEnd = 0;
	lp->cIsMain = 0;
	lp->cEnableSysHook = 0;
	lp->cIsShareStack = at.share_stack != NULL;

	lp->save_size = 0;
	lp->save_buffer = NULL;

	return lp;
}

// 根据指定参数，创建一个协程
int co_create( stCoRoutine_t **ppco,const stCoRoutineAttr_t *attr,pfn_co_routine_t pfn,void *arg )
{
	if( !co_get_curr_thread_env() ) 
	{
		co_init_curr_thread_env();
	}
	stCoRoutine_t *co = co_create_env( co_get_curr_thread_env(), attr, pfn,arg );
	*ppco = co;
	return 0;
}

// 释放协程资源
void co_free( stCoRoutine_t *co )
{
    if (!co->cIsShareStack) 
    {    
        free(co->stack_mem->stack_buffer);
        free(co->stack_mem);
    }   
    //walkerdu fix at 2018-01-20
    //存在内存泄漏
    else 
    {
        if(co->save_buffer)
            free(co->save_buffer);

        if(co->stack_mem->occupy_co == co)
            co->stack_mem->occupy_co = NULL;
    }

    free( co );
}
void co_release( stCoRoutine_t *co )
{
    co_free( co );
}

void co_swap(stCoRoutine_t* curr, stCoRoutine_t* pending_co);

// 启动指定的协程(第一次启动 / 重启挂起的协程)
void co_resume( stCoRoutine_t *co )
{
	stCoRoutineEnv_t *env = co->env;
	// 获得当前调用co_resume接口的协程
	// stCoRoutine_t *lpCurrRoutine = co_self();
	stCoRoutine_t *lpCurrRoutine = env->pCallStack[ env->iCallStackSize - 1 ];
	if( !co->cStart )
	{
		// 待运行的协程co还没有运行过，为其创建上下文和栈空间
		coctx_make( &co->ctx,(coctx_pfn_t)CoRoutineFunc,co,0 );
		co->cStart = 1;
	}
	// 将待执行协程co压入协程调用栈的队尾
	env->pCallStack[ env->iCallStackSize++ ] = co;
	// 将运行资源转移至待执行协程co，完成协程切换。 执行权切换到当前协程，执行函数CoRoutineFunc(执行任务函数co->pfn，并执行yield)
	co_swap( lpCurrRoutine, co );
	// 只有当co中调用yield才会返回父协程lpCurrRoutine中
	// 非对称协程，仅能返回上层调用处
}


// walkerdu 2018-01-14                                                                              
// 用于reset超时无法重复使用的协程                                                                  
void co_reset(stCoRoutine_t * co)
{
    if(!co->cStart || co->cIsMain)
        return;

    co->cStart = 0;
    co->cEnd = 0;

    // 如果当前协程有共享栈被切出的buff，要进行释放
    if(co->save_buffer)
    {
        free(co->save_buffer);
        co->save_buffer = NULL;
        co->save_size = 0;
    }

    // 如果共享栈被当前协程占用，要释放占用标志，否则被切换，会执行save_stack_buffer()
    if(co->stack_mem->occupy_co == co)
        co->stack_mem->occupy_co = NULL;
}

// 执行yield，让出当前协程，恢复至其父协程(当初调用co_resume进来的地方)
// 非对称协程，仅能返回上层调用处
void co_yield_env( stCoRoutineEnv_t *env )
{
	// 父协程
	stCoRoutine_t *last = env->pCallStack[ env->iCallStackSize - 2 ];
	// 当前协程
	stCoRoutine_t *curr = env->pCallStack[ env->iCallStackSize - 1 ];

	env->iCallStackSize--;

	// 返回父协程
	co_swap( curr, last);
}

// 非对称协程，仅能返回上层调用处, 因此无需传入下面要执行的协程
void co_yield_ct()
{

	co_yield_env( co_get_curr_thread_env() );
}

void co_yield( stCoRoutine_t *co )
{
	co_yield_env( co->env );
}

// 将指定协程的栈信息暂存至创建的save_buffer内存中
void save_stack_buffer(stCoRoutine_t* occupy_co)
{
	///copy out
	stStackMem_t* stack_mem = occupy_co->stack_mem;
	int len = stack_mem->stack_bp - occupy_co->stack_sp;

	if (occupy_co->save_buffer)
	{
		free(occupy_co->save_buffer), occupy_co->save_buffer = NULL;
	}

	occupy_co->save_buffer = (char*)malloc(len); //malloc buf;
	occupy_co->save_size = len;

	memcpy(occupy_co->save_buffer, occupy_co->stack_sp, len);
}

// 将当前运行上下文保存至curr协程中，并将pending_co的上下文添加进运行上下文中，以此完成协程的切换
void co_swap(stCoRoutine_t* curr, stCoRoutine_t* pending_co)
{
 	stCoRoutineEnv_t* env = co_get_curr_thread_env();

	//get curr stack sp
	// 新建局部变量c，以获取当前协程栈的栈顶位置
	char c;
	curr->stack_sp= &c;

	if (!pending_co->cIsShareStack)
	{
		// 未使用共享栈，无需处理
		env->pending_co = NULL;
		env->occupy_co = NULL;
	}
	else 
	{
		// 共享栈模式，pending_co需要执行了，需要将其上下文防至指定的栈内存中
		// 由于是共享栈模式，需要提前判断这个栈内存是否还存有之前执行的协程的信息
		env->pending_co = pending_co;
		// 获得上一次在同一个占内存执行过的协程occupy_co
		//get last occupy co on the same stack mem
		stCoRoutine_t* occupy_co = pending_co->stack_mem->occupy_co;
		//set pending co to occupy thest stack mem;
		// 此块栈内存被标记为当前协程pending_co持有
		pending_co->stack_mem->occupy_co = pending_co;

		env->occupy_co = occupy_co;
		if (occupy_co && occupy_co != pending_co)
		{
			// 将occupy_co中栈信息存入其协程创建的save_buffer内存中
			save_stack_buffer(occupy_co);
		}
	}

	//swap context
	coctx_swap(&(curr->ctx),&(pending_co->ctx) );

	//stack buffer may be overwrite, so get again;
	// 此时协程已经完成切换，已经转移至pending_co中，对应的局部变量(协程栈中)也将失效，这里需要重新获取
	stCoRoutineEnv_t* curr_env = co_get_curr_thread_env();
	stCoRoutine_t* update_occupy_co =  curr_env->occupy_co;
	stCoRoutine_t* update_pending_co = curr_env->pending_co;
	
	if (update_occupy_co && update_pending_co && update_occupy_co != update_pending_co)
	{
		//resume stack buffer
		// 恢复当前协程--pending_co中存储在save_buffer中的栈信息至对应的协程栈中
		if (update_pending_co->save_buffer && update_pending_co->save_size > 0)
		{
			memcpy(update_pending_co->stack_sp, update_pending_co->save_buffer, update_pending_co->save_size);
		}
	}
}



//int poll(struct pollfd fds[], nfds_t nfds, int timeout);
// { fd,events,revents }
struct stPollItem_t ;

// poll事件组，通过pPollItems数组管理nfds个stPollItem_t，继承自超时节点
// 每执行一次co_poll_inner会创建一个stPoll_t
struct stPoll_t : public stTimeoutItem_t 
{
	struct pollfd *fds;
	nfds_t nfds; // typedef unsigned long int nfds_t;

	stPollItem_t *pPollItems;

	int iAllEventDetach;

	int iEpollFd;

	// 记录当前事件组触发的事件次数
	int iRaiseCnt;
};

// 一个poll事件，继承自超时节点
struct stPollItem_t : public stTimeoutItem_t
{
	struct pollfd *pSelf;
	stPoll_t *pPoll;

	struct epoll_event stEvent;
};
/*
 *   EPOLLPRI 		POLLPRI    // There is urgent data to read.  
 *   EPOLLMSG 		POLLMSG
 *
 *   				POLLREMOVE
 *   				POLLRDHUP
 *   				POLLNVAL
 *
 * */
// 将poll的设置转换成epoll的设置
static uint32_t PollEvent2Epoll( short events )
{
	uint32_t e = 0;	
	if( events & POLLIN ) 	e |= EPOLLIN;
	if( events & POLLOUT )  e |= EPOLLOUT;
	if( events & POLLHUP ) 	e |= EPOLLHUP;
	if( events & POLLERR )	e |= EPOLLERR;
	if( events & POLLRDNORM ) e |= EPOLLRDNORM;
	if( events & POLLWRNORM ) e |= EPOLLWRNORM;
	return e;
}

// 将epoll的设置转换成poll的设置
static short EpollEvent2Poll( uint32_t events )
{
	short e = 0;	
	if( events & EPOLLIN ) 	e |= POLLIN;
	if( events & EPOLLOUT ) e |= POLLOUT;
	if( events & EPOLLHUP ) e |= POLLHUP;
	if( events & EPOLLERR ) e |= POLLERR;
	if( events & EPOLLRDNORM ) e |= POLLRDNORM;
	if( events & EPOLLWRNORM ) e |= POLLWRNORM;
	return e;
}

// 每个线程共用一个协程环境
static __thread stCoRoutineEnv_t* gCoEnvPerThread = NULL;

// 初始化当前环境，在当前线程上创建一个协程，该线程作为主协程。后续执行的逻辑由该协程发起。使用cIsMain=1标记
// 该主协程永不释放，跟随整个线程生命时期
void co_init_curr_thread_env()
{
	gCoEnvPerThread = (stCoRoutineEnv_t*)calloc( 1, sizeof(stCoRoutineEnv_t) );
	stCoRoutineEnv_t *env = gCoEnvPerThread;

	env->iCallStackSize = 0;
	struct stCoRoutine_t *self = co_create_env( env, NULL, NULL,NULL );
	self->cIsMain = 1;

	env->pending_co = NULL;
	env->occupy_co = NULL;

	coctx_init( &self->ctx );

	env->pCallStack[ env->iCallStackSize++ ] = self;

	// 创建epoll调度器
	stCoEpoll_t *ev = AllocEpoll();
	SetEpoll( env,ev );
}

// 获取当前协程环境
stCoRoutineEnv_t *co_get_curr_thread_env()
{
	return gCoEnvPerThread;
}

// 作为添加epoll事件的回调函数，事件被激活后，先执行OnPollPreparePfn处理事件，随后执行该函数，回到当初创建该事件的协程中，将该事件移除
void OnPollProcessEvent( stTimeoutItem_t * ap )
{
	stCoRoutine_t *co = (stCoRoutine_t*)ap->pArg;
	co_resume( co );
}

// 注册的epoll事件被触发后执行该函数
void OnPollPreparePfn( stTimeoutItem_t * ap,struct epoll_event &e,stTimeoutItemLink_t *active )
{
	stPollItem_t *lp = (stPollItem_t *)ap;
	// 设置当前触发的epoll事件类型
	lp->pSelf->revents = EpollEvent2Poll( e.events );


	stPoll_t *pPoll = lp->pPoll;
	pPoll->iRaiseCnt++;

	// 控制事件仅会被执行一次
	if( !pPoll->iAllEventDetach )
	{
		pPoll->iAllEventDetach = 1;
		// 将当前事件从时间管理器中移除
		RemoveFromLink<stTimeoutItem_t,stTimeoutItemLink_t>( pPoll );
		// 将当前事件加入 待处理(已激活)事件列表中
		AddTail( active,pPoll );

	}
}

// epoll调度器主循环，pfn注册为退出循环的函数，每一轮事件后执行
void co_eventloop( stCoEpoll_t *ctx,pfn_co_eventloop_t pfn,void *arg )
{
	// 为epoll返回的结果res分配相关的内存
	if( !ctx->result )
	{
		ctx->result =  co_epoll_res_alloc( stCoEpoll_t::_EPOLL_SIZE );
	}
	co_epoll_res *result = ctx->result;


	// 主循环
	for(;;)
	{
		// 等待io事件
		int ret = co_epoll_wait( ctx->iEpollFd,result,stCoEpoll_t::_EPOLL_SIZE, 1 );

		stTimeoutItemLink_t *active = (ctx->pstActiveList);
		stTimeoutItemLink_t *timeout = (ctx->pstTimeoutList);

		// 清空超事件列表
		memset( timeout,0,sizeof(stTimeoutItemLink_t) );

		// 处理监听到的ret个事件
		for(int i=0;i<ret;i++)
		{
			stTimeoutItem_t *item = (stTimeoutItem_t*)result->events[i].data.ptr;
			if( item->pfnPrepare )
			{
				// 当前事件注册了处理的函数，直接执行对应的函数，内部逻辑，将该事件从时间管理器移除，将时间放入 待处理(已激活)事件列表active中
				item->pfnPrepare( item,result->events[i],active );
			}
			else
			{
				// 将当前事件添加至待处理(被激活)事件列表中
				AddTail( active,item );
			}
		}


		// 从超时管理器中获取所有超时事件，放入timeout中
		unsigned long long now = GetTickMS();
		TakeAllTimeout( ctx->pTimeout,now,timeout );

		stTimeoutItem_t *lp = timeout->head;
		while( lp )
		{
			//printf("raise timeout %p\n",lp);
			lp->bTimeout = true;
			lp = lp->pNext;
		}

		// 将已经发生超时的事件也加入 待执行(已激活)事件列表中
		Join<stTimeoutItem_t,stTimeoutItemLink_t>( active,timeout );

		// 依次处理待执行(已激活)事件列表中的事件
		lp = active->head;
		while( lp )
		{
			// 弹出头节点
			PopHead<stTimeoutItem_t,stTimeoutItemLink_t>( active );
			// 时超时事件 但 并没有超时，将该事件再一次放入时间管理器中
			// 因为时间管理器仅支持最长60s，当超时事件超过60后会被取模方式对应的时间列表，所以这里需要二次确认下，是否真正的超时了。
            if (lp->bTimeout && now < lp->ullExpireTime) 
			{
				int ret = AddTimeout(ctx->pTimeout, lp, now);
				if (!ret) 
				{
					lp->bTimeout = false;
					lp = active->head;
					continue;
				}
			}
			if( lp->pfnProcess )
			{
				// 内部使用resume，返回到当初设置改事件的协程(业务协程)，在该协程中执行业务代码，直到改协程执行yield再回到当前epoll主循环的逻辑
				lp->pfnProcess( lp );
			}

			lp = active->head;
		}
		// 执行epoll主循环设置的回调函数，用于退出循环
		if( pfn )
		{
			if( -1 == pfn( arg ) )
			{
				break;
			}
		}

	}
}
// @deprecated 废弃函数
void OnCoroutineEvent( stTimeoutItem_t * ap )
{
	stCoRoutine_t *co = (stCoRoutine_t*)ap->pArg;
	co_resume( co );
}

// 创建epoll调度器
stCoEpoll_t *AllocEpoll()
{
	stCoEpoll_t *ctx = (stCoEpoll_t*)calloc( 1,sizeof(stCoEpoll_t) );
	// 创建epoll的fd
	ctx->iEpollFd = co_epoll_create( stCoEpoll_t::_EPOLL_SIZE );
	// 创建时间管理器
	ctx->pTimeout = AllocTimeout( 60 * 1000 );
	// 创建 待处理(已激活)事件列表 和 超时事件列表
	ctx->pstActiveList = (stTimeoutItemLink_t*)calloc( 1,sizeof(stTimeoutItemLink_t) );
	ctx->pstTimeoutList = (stTimeoutItemLink_t*)calloc( 1,sizeof(stTimeoutItemLink_t) );
	return ctx;
}

// 释放epoll调度器资源
void FreeEpoll( stCoEpoll_t *ctx )
{
	if( ctx )
	{
		free( ctx->pstActiveList );
		free( ctx->pstTimeoutList );
		FreeTimeout( ctx->pTimeout );
		co_epoll_res_free( ctx->result );
	}
	free( ctx );
}

// 获取当前协程
stCoRoutine_t *GetCurrCo( stCoRoutineEnv_t *env )
{
	return env->pCallStack[ env->iCallStackSize - 1 ];
}

// 获取当前协程
stCoRoutine_t *GetCurrThreadCo( )
{
	stCoRoutineEnv_t *env = co_get_curr_thread_env();
	if( !env ) return 0;
	return GetCurrCo(env);
}

typedef int (*poll_pfn_t)(struct pollfd fds[], nfds_t nfds, int timeout);
// 添加epoll事件
// fds 为待添加的epoll事件数组
// nfds 为待添加的epoll事件数量
// pollfunc 回调函数，发生错误时执行该函数，并返回
// 返回值为注册的这组事件被调用的次数iRaiseCnt
int co_poll_inner( stCoEpoll_t *ctx,struct pollfd fds[], nfds_t nfds, int timeout, poll_pfn_t pollfunc)
{
    if (timeout == 0)
	{
		return pollfunc(fds, nfds, timeout);
	}
	if (timeout < 0)
	{
		timeout = INT_MAX;
	}
	int epfd = ctx->iEpollFd;
	// 获取当前环境下的协程
	stCoRoutine_t* self = co_self();

	//1.struct change
	stPoll_t& arg = *((stPoll_t*)malloc(sizeof(stPoll_t)));
	memset( &arg,0,sizeof(arg) );

	arg.iEpollFd = epfd;
	arg.fds = (pollfd*)calloc(nfds, sizeof(pollfd));
	arg.nfds = nfds;

	stPollItem_t arr[2];
	if( nfds < sizeof(arr) / sizeof(arr[0]) && !self->cIsShareStack)
	{
		arg.pPollItems = arr;
	}	
	else
	{
		arg.pPollItems = (stPollItem_t*)malloc( nfds * sizeof( stPollItem_t ) );
	}
	memset( arg.pPollItems,0,nfds * sizeof(stPollItem_t) );

	// 注册处理函数，函数的输入参数为当前协程
	// 事件到来时执行，内部执行co_resume，恢复到当前协程
	arg.pfnProcess = OnPollProcessEvent;
	arg.pArg = GetCurrCo( co_get_curr_thread_env() );
	
	
	//2. add epoll
	// 添加epoll事件
	for(nfds_t i=0;i<nfds;i++)
	{
		arg.pPollItems[i].pSelf = arg.fds + i;
		arg.pPollItems[i].pPoll = &arg;

		// 注册预处理函数
		arg.pPollItems[i].pfnPrepare = OnPollPreparePfn;
		struct epoll_event &ev = arg.pPollItems[i].stEvent;

		if( fds[i].fd > -1 )
		{
			ev.data.ptr = arg.pPollItems + i;
			ev.events = PollEvent2Epoll( fds[i].events );

			int ret = co_epoll_ctl( epfd,EPOLL_CTL_ADD, fds[i].fd, &ev );
			if (ret < 0 && errno == EPERM && nfds == 1 && pollfunc != NULL)
			{
				if( arg.pPollItems != arr )
				{
					free( arg.pPollItems );
					arg.pPollItems = NULL;
				}
				free(arg.fds);
				free(&arg);
				return pollfunc(fds, nfds, timeout);
			}
		}
		//if fail,the timeout would work
	}

	//3.add timeout

	unsigned long long now = GetTickMS();
	// 设置失效时间
	arg.ullExpireTime = now + timeout;
	// 将该事件注册进时间管理器
	int ret = AddTimeout( ctx->pTimeout,&arg,now );
	int iRaiseCnt = 0;
	if( ret != 0 )
	{
		co_log_err("CO_ERR: AddTimeout ret %d now %lld timeout %d arg.ullExpireTime %lld",
				ret,now,timeout,arg.ullExpireTime);
		errno = EINVAL;
		iRaiseCnt = -1;

	}
    else
	{
		// 让出协程
		co_yield_env( co_get_curr_thread_env() );
		iRaiseCnt = arg.iRaiseCnt;
	}

	// 事件触发，执行回调函数OnPollProcessEvent，内部执行co_resume，恢复到当前yield出去的地方

	// 从回调函数中resume回来了
    {
		//clear epoll status and memory
		RemoveFromLink<stTimeoutItem_t,stTimeoutItemLink_t>( &arg );
		for(nfds_t i = 0;i < nfds;i++)
		{
			int fd = fds[i].fd;
			if( fd > -1 )
			{
				co_epoll_ctl( epfd,EPOLL_CTL_DEL,fd,&arg.pPollItems[i].stEvent );
			}
			fds[i].revents = arg.fds[i].revents;
		}


		if( arg.pPollItems != arr )
		{
			free( arg.pPollItems );
			arg.pPollItems = NULL;
		}

		free(arg.fds);
		free(&arg);
	}

	return iRaiseCnt;
}

// 添加epoll事件
int	co_poll( stCoEpoll_t *ctx,struct pollfd fds[], nfds_t nfds, int timeout_ms )
{
	return co_poll_inner(ctx, fds, nfds, timeout_ms, NULL);
}

// 设置epoll调度器
void SetEpoll( stCoRoutineEnv_t *env,stCoEpoll_t *ev )
{
	env->pEpoll = ev;
}

// 获取当前协程的epoll调度器，该调度器同个线程内的所有协程共用的
stCoEpoll_t *co_get_epoll_ct()
{
	if( !co_get_curr_thread_env() )
	{
		co_init_curr_thread_env();
	}
	return co_get_curr_thread_env()->pEpoll;
}

// @deprecated，当前未使用
struct stHookPThreadSpec_t
{
	stCoRoutine_t *co;
	void *value;

	enum 
	{
		size = 1024
	};
};
// 获取协程私有变量，底层使用的是线程私有变量
void *co_getspecific(pthread_key_t key)
{
	stCoRoutine_t *co = GetCurrThreadCo();
	if( !co || co->cIsMain )
	{
		return pthread_getspecific( key );
	}
	return co->aSpec[ key ].value;
}
// 设置协程私有变量，底层使用的是线程私有变量
int co_setspecific(pthread_key_t key, const void *value)
{
	stCoRoutine_t *co = GetCurrThreadCo();
	if( !co || co->cIsMain )
	{
		return pthread_setspecific( key,value );
	}
	co->aSpec[ key ].value = (void*)value;
	return 0;
}

// 取消当前协程的hook功能
void co_disable_hook_sys()
{
	stCoRoutine_t *co = GetCurrThreadCo();
	if( co )
	{
		co->cEnableSysHook = 0;
	}
}

// 判断当前协程是否开启hook功能
bool co_is_enable_sys_hook()
{
	stCoRoutine_t *co = GetCurrThreadCo();
	return ( co && co->cEnableSysHook );
}

// 获得当前运行的协程
stCoRoutine_t *co_self()
{
	return GetCurrThreadCo();
}

//co cond
struct stCoCond_t;
// 协程信号量节点，其中存储一个时间节点
struct stCoCondItem_t 
{
	stCoCondItem_t *pPrev;
	stCoCondItem_t *pNext;
	stCoCond_t *pLink;

	stTimeoutItem_t timeout;
};
// 协程信号量，使用链表结构
struct stCoCond_t
{
	stCoCondItem_t *head;
	stCoCondItem_t *tail;
};
static void OnSignalProcessEvent( stTimeoutItem_t * ap )
{
	stCoRoutine_t *co = (stCoRoutine_t*)ap->pArg;
	co_resume( co );
}

stCoCondItem_t *co_cond_pop( stCoCond_t *link );
// 唤醒信号量链表中头节点的协程
int co_cond_signal( stCoCond_t *si )
{
	stCoCondItem_t * sp = co_cond_pop( si );
	if( !sp ) 
	{
		return 0;
	}
	RemoveFromLink<stTimeoutItem_t,stTimeoutItemLink_t>( &sp->timeout );

	AddTail( co_get_curr_thread_env()->pEpoll->pstActiveList,&sp->timeout );

	return 0;
}
// 唤醒信号量链表中所有的协程
int co_cond_broadcast( stCoCond_t *si )
{
	for(;;)
	{
		// 获取信号量链表中的头节点
		stCoCondItem_t * sp = co_cond_pop( si );
		if( !sp ) return 0;

		// 将该协程任务从时间管理器中移除
		RemoveFromLink<stTimeoutItem_t,stTimeoutItemLink_t>( &sp->timeout );
		// 将当前协程任务加入待处理(被激活)事件列表，等待处理
		AddTail( co_get_curr_thread_env()->pEpoll->pstActiveList,&sp->timeout );
	}

	return 0;
}

// 将当前协程挂载到信号量的链表中，以便后续被唤醒
int co_cond_timedwait( stCoCond_t *link,int ms )
{
	stCoCondItem_t* psi = (stCoCondItem_t*)calloc(1, sizeof(stCoCondItem_t));
	// 将当前协程信息注册进时间管理器中，到达时间后resume回当前协程
	psi->timeout.pArg = GetCurrThreadCo();
	psi->timeout.pfnProcess = OnSignalProcessEvent;

	if( ms > 0 )
	{
		unsigned long long now = GetTickMS();
		psi->timeout.ullExpireTime = now + ms;

		int ret = AddTimeout( co_get_curr_thread_env()->pEpoll->pTimeout,&psi->timeout,now );
		if( ret != 0 )
		{
			free(psi);
			return ret;
		}
	}
	AddTail( link, psi);

	// 交出协程控制权
	co_yield_ct();

	//下面代码在注册在时间管理器pTimeout中的事件到时被处理后执行OnSignalProcessEvent中的resume，回到该位置，释放该节点资源。

	RemoveFromLink<stCoCondItem_t,stCoCond_t>( psi );
	free(psi);

	return 0;
}

// 创建一个协程信号量
stCoCond_t *co_cond_alloc()
{
	return (stCoCond_t*)calloc( 1,sizeof(stCoCond_t) );
}

// 释放一个协程信号量
int co_cond_free( stCoCond_t * cc )
{
	free( cc );
	return 0;
}

// 将信号量中的头节点弹出
stCoCondItem_t *co_cond_pop( stCoCond_t *link )
{
	stCoCondItem_t *p = link->head;
	if( p )
	{
		PopHead<stCoCondItem_t,stCoCond_t>( link );
	}
	return p;
}
