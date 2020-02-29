

const void         *text_end(void);

const unsigned char rodata_end[]=
			{ 'm','a','r','k','e','r','e','n','d' };

__attribute__((visibility("default")))
const void* text_end(){
    return (void *)text_end;
}