/*
 *  C++ Program to Implement Weight Balanced Tree
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "struct.h"

/* class WBTNode */
class WBTNode
{
	public:
		WBTNode *left;
		WBTNode *right;
		int weight, key; 
		WBTNode(int key, int wt): left(NULL), right(NULL)
	{
		this->key = key;
		this->weight = wt;
	}
};

/* class WeightBalancedTree */
class WeightBalancedTree
{
	enum {
		INORDER = 0,
		PREORDER = 1,
		POSTORDER = 2
	};
	WBTNode *root;
	public:     
	/* Constructor */
	WeightBalancedTree(void): root(NULL)
	{ }

	/* Function to check if tree is empty */
	bool isEmpty(void)
	{
		return root == NULL;
	}

	WBTNode* getRoot(void)
	{
		return root;
	}


	private:
	WBTNode *_insert(int key, int wt, WBTNode *t)
	{
		WBTNode *nd;
		int lwt, rwt, n;

		if (t == NULL) {
			t = new WBTNode(key, wt);
		}
		else if (key < t->key) {
			n = (t->left == NULL)? 0 : t->left->weight;
			rwt = t->weight - n;
			t->left = _insert (key, wt, t->left);
			lwt = t->left->weight;
			if (lwt > rwt) {
				t->left->weight += rwt;
				nd = t->left->right;
				t->weight = rwt + (nd == NULL) ? 0 : nd->weight;
				t = _rotateWithLeftChild (t);
			}
			else
				t->weight += wt;
		}
		else if (key > t->key) {
			n = (t->right == NULL)? 0 : t->right->weight;
			lwt = t->weight - n;
			t->right = _insert (key, wt, t->right);
			rwt = t->right->weight;
			if (lwt < rwt) {
				t->right->weight += lwt;
				nd = t->right->left;
				t->weight = lwt + (nd == NULL) ? 0 : nd->weight;
				t = _rotateWithRightChild (t);
			}
			else 
				t->weight += wt;
		}
		return t;
	}

	/* Rotate tree node with left child  */     
	WBTNode *_rotateWithLeftChild (WBTNode *k2)
	{
		WBTNode *k1 = k2->left;
		k2->left = k1->right;
		k1->right = k2;
		return k1;
	}

	/* Rotate tree node with right child */
	WBTNode *_rotateWithRightChild (WBTNode *k1)
	{
		WBTNode *k2 = k1->right;
		k1->right = k2->left;
		k2->left = k1;
		return k2;
	}

	/* Functions for tree traversal */
	void _walkTree(WBTNode* t, int VIST)
	{
		if (t == NULL)
			return;

		switch(VIST) {
			case INORDER:
				_walkTree(t->left, VIST);
				printf("%x\t", t->key);
				_walkTree(t->right, VIST);
				break;
			case PREORDER:
				printf("%x\t", t->key);
				_walkTree(t->left, VIST);             
				_walkTree(t->right, VIST);
				break;
			case POSTORDER:

				_walkTree(t->left, VIST);             
				_walkTree(t->right, VIST);
				printf("%x\t", t->key);
				break;
			default:
				exit(1);
		}
	}
	public:
	/* Functions to insert data */
	void insert(int key, int wt)
	{
		root = _insert(key, wt, root);
	}

	void walk(int VIST)
	{
		if ((VIST != INORDER) && (VIST != PREORDER) && (VIST != POSTORDER))
			perror("Invalid VIST order");
		else {
			_walkTree(root, VIST);
			printf("\n");
		}
	}
};

class CodeGenerator{
	static CodeGenerator *instance;
	WeightBalancedTree *tree;
	asmcode_blk_t *s;
	char* label0;
	CodeGenerator(void){}

	public:
	static CodeGenerator* createGenerator(void)
	{
		if (instance == NULL) {
			instance = new CodeGenerator;
			instance->tree = NULL;
			instance->label0 = NULL;
		}
		return instance;
	}

	void initGenerator(WeightBalancedTree *tree, asmcode_blk_t *s, char *label)
	{
		if ((tree == NULL) || (label == NULL)){
			printf("empty tree;\n");
			exit(0);
		}
		this->tree = tree;
		if (label0 != NULL)
			free(label0);
		this->s = s;
		label0 = strdup(label);
	}

	void genCode(void)
	{
		WBTNode *root;

		root = tree->getRoot();
		if (root != NULL) {
			_genCode(root, label0);
			(s->sprintf) (s, "%s%s:\n", label0, "_exit");
		}
	}
	private:
	void _genCode(WBTNode *nd, const char* label)
	{
		char *bufl, *bufr;

		(s->sprintf) (s, "%s:\n", label);
		(s->sprintf) (s, "\tcmp    glab_%08x,%%eax\n", nd->key);
		if (nd->left != NULL) 
		{
			bufl = (char*)malloc(strlen(label)+8);		
			strcpy(stpcpy(bufl, label), "l");
			(s->sprintf) (s, "\tjl     %s\n", bufl);
		}

		bufr = (char*)malloc(strlen(label)+8);		
		if (nd->right != NULL) 
			strcpy(stpcpy(bufr, label), "r");
		else
			strcat(stpcpy(bufr, label0), "_exit");

		(s->sprintf) (s, "\tjnz    %s\n", bufr);
		(s->sprintf) (s, "\tjmp    glab_%08x\n", nd->key);
		if (nd->left != NULL)
			_genCode(nd->left, bufl);
		if (nd->right != NULL)
			_genCode(nd->right, bufr);
	}
};

CodeGenerator* CodeGenerator::instance = NULL;

static void* xmalloc(size_t size)
{
	void *p = malloc(size);
	if (p == NULL) {
		perror("Out of memory");
		exit(EXIT_FAILURE);
	}
	return p;
}

static void* xrealloc(void *ptr, size_t size)
{
	void *p = realloc(ptr, size);
	if (p == NULL) {
		perror("Out of memory");
		exit(EXIT_FAILURE);
	}
	return p;
}

	int __attribute__ ((format (printf, 2, 3)))
objdump_sprintf (asmcode_blk_t *f, const char *format, ...) 
//__attribute__ ((format (printf, 2, 3)))
{
	size_t n;
	va_list args;

	while (1) {
		size_t space = f->alloc - f->pos;

		va_start (args, format);
		n = vsnprintf (f->buffer + f->pos, space, format, args);
		va_end (args);

		if (space > n) 
			break;

		f->alloc = (f->alloc + n) * 2; 
		f->buffer = (char *) xrealloc (f->buffer, f->alloc);
	}    
	f->pos += n;

	return n;
}

asmcode_blk_t* explicitate_cfi (cfi_info_t *info, asmcode_blk_t** blk)
{
	if ((info == NULL) || (info->pos == 0))
		return NULL;

	CodeGenerator *gen = CodeGenerator::createGenerator();
	WeightBalancedTree wbt;
	asmcode_blk_t *sfile;
	char label[32];
	int i;

	for (i = 0; i< info->pos; i++) {
		wbt.insert(info->info[i].tovma, info->info[i].freq);
	}

	if (blk != NULL)
		sfile = *blk;
	else 
		sfile = NULL;

	if (sfile == NULL)
		sfile = (asmcode_blk_t*)xmalloc(sizeof(asmcode_blk_t));    
	if (sfile->buffer == NULL) {
		sfile->alloc = info->pos * 4 * 15;
		sfile->buffer = (char*)xmalloc(sfile->alloc);
		sfile->sprintf = (sprintf_ft) objdump_sprintf;
	}
	snprintf(label, 32, "lab%lx", info->fromvma);
	gen->initGenerator(&wbt, sfile, label);
	gen->genCode();

	return sfile;
}

