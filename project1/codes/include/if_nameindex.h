#ifndef _CSC_IF_NAMEINDEX
#define _CSC_IF_NAMEINDEX

#include <net/if.h>

struct IfNameIndex {
    struct iterator {
       public:
        iterator(struct if_nameindex* index);

        void drop();

        iterator& operator++();
        struct if_nameindex& operator*();

        bool operator==(const iterator& other) const;
        bool operator!=(const iterator& other) const;

       private:
        struct if_nameindex* current;
    };

    IfNameIndex();
    ~IfNameIndex();

    iterator begin();
    iterator end();

   private:
    iterator head;
};

#endif