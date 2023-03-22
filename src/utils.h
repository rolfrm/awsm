#include <stdint.h>
typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef char * str;

typedef float f32;
typedef double f64;


#define STRINGIZE_DETAIL(x) #x
#define STRINGIZE(x) STRINGIZE_DETAIL(x)

#define array_element_size(array) sizeof(array[0])
#define array_count(array) (sizeof(array)/array_element_size(array))


#define UNUSED1(x) (void)(x)
#define UNUSED2(x,y) UNUSED1(x);UNUSED1(y);
#define UNUSED3(x,y,z) UNUSED2(x,y);UNUSED1(z);
#define UNUSED4(x,y,z,w) UNUSED2(x,y);UNUSED2(z,w);
#define UNUSED5(x,y,z,w,v) UNUSED2(x,y);UNUSED2(z,w);UNUSED1(v);
#define GET_MACRO(_1, _2, _3, _4, _5, NAME,...) NAME
#define UNUSED(...) GET_MACRO(__VA_ARGS__, UNUSED5, UNUSED4, UNUSED3, UNUSED2, UNUSED1, ...)(__VA_ARGS__)
#ifdef __APPLE__
#undef USE_VALGRIND
#endif

#ifdef USE_VALGRIND
#include <valgrind/memcheck.h>
#define MAKE_UNDEFINED(x) VALGRIND_MAKE_MEM_UNDEFINED(&(x),sizeof(x));
#define MAKE_NOACCESS(x) VALGRIND_MAKE_MEM_NOACCESS(&(x),sizeof(x));
#else
#define MAKE_UNDEFINED(x) UNUSED(x);
#define MAKE_NOACCESS(x) UNUSED(x);
#endif

#define auto __auto_type
#define var __auto_type
#define let __auto_type const

#define WARN_UNUSED __attribute__((warn_unused_result))
#define FALLTHROUGH  __attribute__ ((fallthrough));
    
      

#define MAX(a,b) \
   ({ auto _a = (a); \
       auto _b = (b); \
     _a > _b ? _a : _b; })

#define POP(a,b)     \
  ({ auto _a = (a);  \
    a = (b);	     \
    _a; })


#define MIN(a,b) \
   ({ auto _a = (a); \
       auto _b = (b); \
     _a < _b ? _a : _b; })

#define CLAMP(value, min, max)({					\
      auto _value = value; auto _min = min; auto _max = max;		\
      _value < _min ? _min : _value > _max ? _max : _value;		\
    })

#define ABS(a) ({ auto _a = a; _a < 0 ? -_a : _a;})

// gets the sign of value -1 or 1.
//#define SIGN(x) (x < 0 ? -1 : 1)
#define SIGN(x) (x > 0 ? 1 : (x < 0 ? -1 : 0))


#define lambda(return_type, body_and_args) \
  ({ \
    return_type __fn__ body_and_args \
    __fn__; \
  })

// swap two variables. Each should be same type
#define SWAP(x,y){ auto tmp = x; x = y; y = tmp;}
#define SWAPCALL(e,x,y)if(e){x;y;}else{y;x;}
// set location to a new value, Return previous value.
#define REPLACE(location,newv)({int tmp = location; location = newv; tmp;})

void iron_register_deinitializer(void (* f)(void * data), void * data);
void iron_deinitialize(void);
void __test_utils(void);
void print_raw(void * data, size_t size);
