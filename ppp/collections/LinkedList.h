#pragma once

#include <ppp/stdafx.h>

namespace ppp 
{
    namespace collections 
    {
        template <typename T>
        class LinkedList;

        template <typename T>
        struct LinkedListNode
        {
        public:
        	std::shared_ptr<LinkedListNode<T> > Previous;
        	std::shared_ptr<LinkedListNode<T> > Next;
        	T                                   Value;
        	LinkedList<T>*                      LinkedList_;
        };

        template <typename T>
        class LinkedList final
        {
        private:
        	std::shared_ptr<LinkedListNode<T> > m_first;
        	std::shared_ptr<LinkedListNode<T> > m_last;
        	int 								m_count;

        public:
        	LinkedList() noexcept
        	{
        		this->m_count = 0;
        		this->m_first = NULLPTR;
        		this->m_last = NULLPTR;
        	}
			~LinkedList() noexcept
			{
				Clear();
			}

		public:
        	std::shared_ptr<LinkedListNode<T> > First() noexcept;
        	std::shared_ptr<LinkedListNode<T> > Last() noexcept;
        	int                                 Count() noexcept;
        	bool                                IsEmpty() noexcept;
        	bool                                AddFirst(std::shared_ptr<LinkedListNode<T> > value) noexcept;
        	bool                                AddLast(std::shared_ptr<LinkedListNode<T> > value) noexcept;
        	bool                                AddAfter(std::shared_ptr<LinkedListNode<T> > node, std::shared_ptr<LinkedListNode<T> > value) noexcept;
        	bool                                AddBefore(std::shared_ptr<LinkedListNode<T> > node, std::shared_ptr<LinkedListNode<T> > value) noexcept;
        	bool                                RemoveFirst() noexcept;
        	bool                                RemoveLast() noexcept;
        	bool                                Remove(std::shared_ptr<LinkedListNode<T> > node) noexcept;
        	std::shared_ptr<LinkedListNode<T> > Find(T value) noexcept;
        	void                                Clear() noexcept;
        };

        template <typename T>
        inline std::shared_ptr<LinkedListNode<T> > LinkedList<T>::First() noexcept
        {
        	return this->m_first;
        }

        template <typename T>
        inline std::shared_ptr<LinkedListNode<T> > LinkedList<T>::Last() noexcept
        {
        	return this->m_last;
        }

        template <typename T>
        inline int LinkedList<T>::Count() noexcept
        {
        	return this->m_count;
        }

        template <typename T>
        inline bool LinkedList<T>::IsEmpty() noexcept
        {
        	return this->m_count < 1;
        }

        template <typename T>
        inline bool LinkedList<T>::AddFirst(std::shared_ptr<LinkedListNode<T> > value) noexcept
        {
        	if (value == NULLPTR)
        	{
        		return false;
        	}

        	value->LinkedList_ = NULLPTR;
        	value->Next = NULLPTR;
        	value->Previous = NULLPTR;

        	if (this->m_last == NULLPTR)
        	{
        		this->m_last = value;
        		this->m_first = value;
        		this->m_count = 0;
        	}
        	else
        	{
        		std::shared_ptr<LinkedListNode<T> > current = this->m_first;
        		value->Next = current;
        		current->Previous = value;
        		this->m_first = value;
        	}

        	this->m_count++;
        	value->LinkedList_ = this;
        	return true;
        }

        template <typename T>
        inline bool LinkedList<T>::AddLast(std::shared_ptr<LinkedListNode<T> > node) noexcept
        {
        	if (node == NULLPTR)
        	{
        		return false;
        	}

        	node->LinkedList_ = NULLPTR;
        	node->Next = NULLPTR;
        	node->Previous = NULLPTR;

        	if (this->m_last == NULLPTR)
        	{
        		this->m_first = node;
        		this->m_last = node;
        		this->m_count = 0;

        		this->m_count++;
        		node->LinkedList_ = this;
        		return true;
        	}
        	else
        	{
        		return this->AddAfter(this->m_last, node);
        	}
        }

        template <typename T>
        inline bool LinkedList<T>::AddAfter(std::shared_ptr<LinkedListNode<T> > node, std::shared_ptr<LinkedListNode<T> > value) noexcept
        {
        	if (node == NULLPTR || value == NULLPTR)
        	{
        		return false;
        	}

        	value->LinkedList_ = NULLPTR;
        	value->Next = NULLPTR;
        	value->Previous = NULLPTR;

        	std::shared_ptr<LinkedListNode<T> > current = node->Next;
        	node->Next = value;
        	if (current != NULLPTR)
        	{
        		current->Previous = value;
        	}

        	value->Previous = node;
        	value->Next = current;
        	if (node == this->m_last)
        	{
        		this->m_last = value;
        	}

        	this->m_count++;
        	value->LinkedList_ = this;
        	return true;
        }

        template <typename T>
        inline bool LinkedList<T>::AddBefore(std::shared_ptr<LinkedListNode<T> > node, std::shared_ptr<LinkedListNode<T> > value) noexcept
        {
        	if (node == NULLPTR || value == NULLPTR)
        	{
        		return false;
        	}

        	value->LinkedList_ = NULLPTR;
        	value->Next = NULLPTR;
        	value->Previous = NULLPTR;

        	LinkedListNode<T> current = node->Previous;
        	if (current == NULLPTR)
        	{
        		return this->AddFirst(value);
        	}

        	current.Next = value;
        	node->Previous = value;
        	value->Next = node;
        	value->Previous = current;
        	if (node == this->m_first)
        	{
        		this->m_first = value;
        	}

        	this->m_count++;
        	value->LinkedList_ = this;
        	return true;
        }

        template <typename T>
        inline bool LinkedList<T>::RemoveFirst() noexcept
        {
        	std::shared_ptr<LinkedListNode<T> > first = this->m_first;
        	if (first == NULLPTR)
        	{
        		return false;
        	}

        	std::shared_ptr<LinkedListNode<T> > current = first->Next;
        	first->Previous = NULLPTR;
        	first->LinkedList_ = NULLPTR;
        	first->Next = NULLPTR;
        	if (current != NULLPTR)
        	{
        		current->Previous = NULLPTR;
        	}

        	this->m_count--;
        	if (this->m_count <= 0)
        	{
        		this->m_count = 0;
        		this->m_first = NULLPTR;
        		this->m_last = NULLPTR;
        		current = NULLPTR;
        	}

        	this->m_first = current;
        	return true;
        }

        template <typename T>
        inline bool LinkedList<T>::RemoveLast() noexcept
        {
        	std::shared_ptr<LinkedListNode<T> > last = this->m_last;
        	if (last == NULLPTR)
        	{
        		return false;
        	}

        	std::shared_ptr<LinkedListNode<T> > current = last->Previous;
        	last->Previous = NULLPTR;
        	last->LinkedList_ = NULLPTR;
        	last->Next = NULLPTR;
        	if (current != NULLPTR)
        	{
        		current->Next = NULLPTR;
        	}

        	this->m_count--;
        	if (this->m_count <= 0)
        	{
        		this->m_count = 0;
        		this->m_first = NULLPTR;
        		this->m_last = NULLPTR;
        		current = NULLPTR;
        	}

        	this->m_last = current;
        	return true;
        }

        template <typename T>
        inline bool LinkedList<T>::Remove(std::shared_ptr<LinkedListNode<T> > node) noexcept
        {
        	if (node == NULLPTR)
        	{
        		return false;
        	}

        	if (node == this->m_first)
        	{
        		return this->RemoveFirst();
        	}

        	if (node == this->m_last)
        	{
        		return this->RemoveLast();
        	}

        	std::shared_ptr<LinkedListNode<T> > previous = node->Previous;
        	std::shared_ptr<LinkedListNode<T> > next = node->Next;
        	previous->Next = next;
        	next->Previous = previous;

        	this->m_count--;
        	if (this->m_count <= 0)
        	{
        		this->m_count = 0;
        		this->m_first = NULLPTR;
        		this->m_last = NULLPTR;
        	}

        	node->Next = NULLPTR;
        	node->Previous = NULLPTR;
        	node->LinkedList_ = NULLPTR;
        	return true;
        }

        template <typename T>
        inline std::shared_ptr<LinkedListNode<T> > LinkedList<T>::Find(T value) noexcept
        {
        	std::shared_ptr<LinkedListNode<T> > i = this->m_first;
        	while (i != NULLPTR)
        	{
        		if (i->Value == value)
        		{
        			return i;
        		}
                else 
                {
        		    i = i->Next;
                }
        	}
        	return NULLPTR;
        }

        template <typename T>
        inline void LinkedList<T>::Clear() noexcept
        {
        	std::shared_ptr<LinkedListNode<T> > i = this->m_first;
        	while (i != NULLPTR)
        	{
        		std::shared_ptr<LinkedListNode<T> > j = i->Next;
        		{
        			i->LinkedList_ = NULLPTR;
        			i->Next = NULLPTR;
        			i->Previous = NULLPTR;
        		}
        		i = j;
        	}

        	this->m_first = NULLPTR;
        	this->m_count = 0;
        	this->m_last = NULLPTR;
        }
    }
}