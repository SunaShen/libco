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


#ifndef __CO_ROUTINE_INNER_H__

#include "co_routine.h"
#include "coctx.h"
struct stCoRoutineEnv_t;

// 指向存储变量的地址
struct stCoSpec_t
{
	void *value;
};

// 栈内存结构体
struct stStackMem_t
{
	// 正在使用该协程栈的协程
	// TODO : 仅共享栈模式有效
	stCoRoutine_t* occupy_co;
	// 栈的大小
	int stack_size;
	// 栈底，栈的数据从高地址到低地址，即stack_buffer + stack_size
	char* stack_bp; //stack_buffer + stack_size
	// 栈内容存储的位置(栈顶)
	char* stack_buffer;

};

// 共享栈结构体，其中包含多个协程栈
struct stShareStack_t
{
	// 正在使用的协程栈的索引
	unsigned int alloc_idx;
	// 协程栈的大小 = sizeof(stStackMem_t*)
	int stack_size;
	// 共享栈的大小
	int count;
	// 共享栈的内容，为指针数据，各个指针指向不同的栈内存
	stStackMem_t** stack_array;
};



// 协程结构
struct stCoRoutine_t
{
	// 协程运行的环境，每个线程创建一个，当前线程所有协程共享
	stCoRoutineEnv_t *env;
	// 协程对应的函数
	pfn_co_routine_t pfn;
	// 协程对应函数的输入参数
	void *arg;
	// 协程上下文信息，包含寄存器和栈信息
	coctx_t ctx;

	// 协程的状态
	char cStart;
	char cEnd;
	char cIsMain;
	char cEnableSysHook;
	char cIsShareStack;

	void *pvEnv;

	//char sRunStack[ 1024 * 128 ];
	// 栈内存
	stStackMem_t* stack_mem;


	//save satck buffer while confilct on same stack_buffer;
	// 协程栈的栈顶
	char* stack_sp; 
	// save_buffer的长度
	unsigned int save_size;
	// 协程挂起时，栈的内容会暂存至save_buffer中
	char* save_buffer;

	// 使用线程变量存储协程私有变量
	// pthread_key_create 创建key
	// pthread_setspecific 存储值
	// pthread_getspecific 获取值
	// pthread_key_delete 回收线程私有变量
	stCoSpec_t aSpec[1024];

};



//1.env
// 初始化协程环境
void 				co_init_curr_thread_env();
// 获得当前协程环境
stCoRoutineEnv_t *	co_get_curr_thread_env();

//2.coroutine
// 释放协程资源
void    co_free( stCoRoutine_t * co );
// 让出协程执行权
void    co_yield_env(  stCoRoutineEnv_t *env );

//3.func



//-----------------------------------------------------------------------------------------------

struct stTimeout_t;
struct stTimeoutItem_t ;

// 创建时间管理器
stTimeout_t *AllocTimeout( int iSize );
// 释放时间管理器
void 	FreeTimeout( stTimeout_t *apTimeout );
// 往时间管理器中添加定时事件
int  	AddTimeout( stTimeout_t *apTimeout,stTimeoutItem_t *apItem ,uint64_t allNow );

// epoll管理器相关
struct stCoEpoll_t;
// 创建epoll管理器
stCoEpoll_t * AllocEpoll();
// 释放epoll管理器
void 		FreeEpoll( stCoEpoll_t *ctx );

// 获取当前协程
stCoRoutine_t *		GetCurrThreadCo();
// 将epoll管理器设置至协程环境中
void 				SetEpoll( stCoRoutineEnv_t *env,stCoEpoll_t *ev );

typedef void (*pfnCoRoutineFunc_t)();

#endif

#define __CO_ROUTINE_INNER_H__
