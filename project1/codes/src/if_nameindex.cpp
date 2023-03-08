#include "if_nameindex.h"

#include <string.h>

#include <iostream>

IfNameIndex::iterator::iterator(struct if_nameindex* index) : current(index) {
    std::cerr << "IfNameIndex::iterator(" << index << ")" << std::endl;
}

void IfNameIndex::iterator::drop() {
    std::cerr << "IfNameIndex::drop(" << current << ")" << std::endl;
    if_freenameindex(this->current);
}

IfNameIndex::iterator& IfNameIndex::iterator::operator++() {
    this->current++;
    return *this;
}

bool IfNameIndex::iterator::operator==(const iterator& other) const {
    if (this->current == other.current) return true;
    if (this->current == nullptr) {
        return other.current->if_index == 0 &&
               other.current->if_name == nullptr;
    }
    if (other.current == nullptr) {
        return this->current->if_index == 0 &&
               this->current->if_name == nullptr;
    }
    return this->current->if_index == other.current->if_index &&
           strcmp(this->current->if_name, other.current->if_name) == 0;
}

bool IfNameIndex::iterator::operator!=(const iterator& other) const {
    return !this->operator==(other);
}

struct if_nameindex& IfNameIndex::iterator::operator*() {
    return *this->current;
}

IfNameIndex::IfNameIndex() : head(if_nameindex()) {}
IfNameIndex::~IfNameIndex() { head.drop(); }

auto IfNameIndex::begin() -> iterator { return this->head; }
IfNameIndex::iterator IfNameIndex::end() { return iterator(nullptr); }