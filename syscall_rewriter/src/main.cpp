#include "syscall_rewriting.hpp"

vector<Syscall *> *get_all_syscalls(CodeObject *codeObject);
void remove_unrewritable(vector<Syscall *> *syscall_list, vector<Syscall *> *sc_prev_list);
bool block_too_small(Block *next_block);
bool is_target(Block *syscall_block, Block *next_block);
bool uses_rip(Block *next_block);
bool uses_fs(Block *next_block);
bool has_incompatible_instruction(Block *next_block);
void rewrite_syscall(Syscall *syscall);
void write_assembly_to_file(vector<Syscall *> *syscall_list, vector<Syscall *> *sc_prev_list, string prog_name);
void compile_hermitcore();
uint64_t prev_use_rip(Block *sc_block, Address prev_addr, Address sc_addr);
char *copy_file(char *progName);
string get_objdump(string prog_name);
void rewrite_syscalls(vector<Syscall *> *syscall_list, vector<Syscall *> *sc_prev_list, char *progName);

/* We rewrite only selected syscalls */
vector<uint64_t> syscall_whitelist;

int main(int argc, char *argv[])
{
	if (argc < 3)
	{
		printf("Usage: %s <path-to-application-binary> <addr1> [addr2] [addr3] etc.\n", argv[0]);
		printf("  Addresses correspond to a whitelist of syscall instruction addresses to rewrite\n");
		printf("  all other syscalls will not be rewritten. Addresses shoud be in HEX\n");
		return -1;
	}
	char *progName = argv[1];
	//path of program to be repaced
	string progNameStr(progName);

	SymtabCodeSource *sts;
	CodeObject *co;
	PatchObject *po, *clonedpo;
	Instruction::Ptr instr;
	SymtabAPI::Symtab *symTab;
	vector<Syscall *> *syscall_list = new vector<Syscall *>();
	vector<Syscall *> *sc_prev_list = new vector<Syscall *>();

	/* Store all considered syscall invocation addresses */
	for (int i = 2; i < argc; i++)
		syscall_whitelist.push_back(strtoull(argv[i], NULL, 16));
	//push some syscalls to be written in the argv into syscall_whitelist

	if (!SymtabAPI::Symtab::openFile(symTab, progNameStr))
	{
		cout << "File can not be parsed\n";
		return -1;
	}

	//load all code of program into CodeObject co
	sts = new SymtabCodeSource(progName);
	co = new CodeObject(sts);
	co->parse();

	syscall_list = get_all_syscalls(co);
	printf("%ld syscalls found \n", syscall_list->size());

	remove_unrewritable(syscall_list, sc_prev_list);
	printf("%zd syscalls will be overwritten\n", syscall_list->size());

	if (!(syscall_list->size() + sc_prev_list->size()))
		exit(0);
	//wtire to new.s
	write_assembly_to_file(syscall_list, sc_prev_list, progNameStr);

	//???

	// TODO:
	compile_hermitcore();
	//write hermitcore? ver. program to program_fast
	char *new_file = copy_file(progName);
	rewrite_syscalls(syscall_list, sc_prev_list, new_file);

	printf("Rewriting completed successfully\n");
	return 0;
}

static inline bool is_whitelisted(uint64_t addr)
{
	return (std::find(syscall_whitelist.begin(), syscall_whitelist.end(), addr) != syscall_whitelist.end());
}

vector<Syscall *> *get_all_syscalls(CodeObject *codeObject)
{
	vector<Syscall *> *syscall_list = new vector<Syscall *>;

	const CodeObject::funclist &funcs = codeObject->funcs();
	if (funcs.size() == 0)
	{
		cout << "No functions in file\n";
		exit(1);
	}
	cout << funcs.size() << " functions found\n";

	for (auto f1 = funcs.begin(); f1 != funcs.end(); ++f1)
	{
		Function *f = *f1;
		const Function::blocklist &bblocks = f->blocks();

		for (auto j = bblocks.begin(); j != bblocks.end(); ++j)
		{
			Block *bb = *j;
			Block::Insns instructions;
			bb->getInsns(instructions);

			if (instructions.size() == 0)
			{
				cout << "No instructions";
				continue;
			}

			for (auto k = instructions.begin(); k != instructions.end(); ++k)
			{
				Instruction::Ptr instr(new Dyninst::InstructionAPI::Instruction(k->second));
				uint64_t addr = k->first;
				Operation op = instr->getOperation();

				string mnemonic = op.format();
				bool already_caught = any_of(syscall_list->begin(), syscall_list->end(),
											 [&](Syscall *s)
											 { return addr == s->get_address(); });
				if (!mnemonic.compare("syscall") and !already_caught)
				{
					if (1 || is_whitelisted(addr))
					{
						Syscall *sc = new Syscall(f, bb, instr, addr);
						syscall_list->push_back(sc);
					}
				}
			}
		}
	}
	return syscall_list;
}
void remove_unrewritable(vector<Syscall *> *syscall_list, vector<Syscall *> *sc_prev_list)
{
	vector<Syscall *> to_remove;
	//int nonextblock = 0, unwantedbranch = 0, ripdependent = 0, hasjmp = 0;
	int prevc = 0;
	for (auto it = syscall_list->begin(); it != syscall_list->end(); ++it)
	{
		int coz = 0;
		Syscall *sc = *it;
		Block *scblock = sc->get_sc_block();
		Block *nextblock = sc->get_next_block();
		cout << hex << sc->get_address() << endl;
		if (nextblock)
		{
			cout << nextblock->size() << endl;
		}
		/* No block following the syscall or next block is too small. */
		if (block_too_small(nextblock))
		{
			coz |= 1;
		}
		/* Syscall block should be the only source for the next block */
		else if (is_target(scblock, nextblock))
		{
			coz |= 2;
		}
		//cout<<"coz="<<coz<<endl;
		/* If replaced instructions use the value of RIP */
		else if (uses_rip(nextblock))
		{
			coz |= 4;
		}
		else if (uses_fs(nextblock))
		{
			coz |= 8;
		}
		else if (has_incompatible_instruction(nextblock))
		{
			coz |= 16;
		}
		cout << "coz=" << coz << endl;
		if (coz)
		{
			to_remove.push_back(sc);
			if (sc->get_prev_address() == -1 || sc->get_prev_len() < 3)
			{
				cout << "this syscall can't be rewrite now\n";
			}
			else
			{
				if (prev_use_rip(scblock, sc->get_prev_address(), sc->get_address()))
				{
					cout << "rip problem" << endl;
				}
				else
				{
					sc_prev_list->push_back(sc);
					prevc++;
				}
			}
		}
	}
	cout << oct << prevc << " sc will be prev write." << endl;
	/* printf("NNB: %d \nUB: %d \nRIP: %d \nJMP: %d\n",
		   nonextblock, unwantedbranch, ripdependent, hasjmp); */

	for (auto it = to_remove.begin(); it != to_remove.end(); ++it)
	{
		Syscall *sc = *it;
		auto tr = remove(syscall_list->begin(), syscall_list->end(), sc);
		syscall_list->erase(tr);
	}
}

bool block_too_small(Block *nextblock)
{
	return nextblock == nullptr || nextblock->size() < EXTRA_OW_BYTES;
}

bool is_target(Block *syscall_block, Block *next_block)
{
	const Block::edgelist &elist = next_block->sources();
	return !(elist.size() == 1 && (*elist.begin())->src() == syscall_block);
}

uint64_t prev_use_rip(Block *sc_block, Address prev_addr, Address sc_addr)
{
	Block::Insns instructions;
	sc_block->getInsns(instructions);
	for (auto k = instructions.begin(); k != instructions.end(); ++k)
	{
		Address addr = k->first;
		if (addr < prev_addr)
			continue;
		if (addr == sc_addr)
			break;
		Instruction::Ptr instr(new Dyninst::InstructionAPI::Instruction(k->second));
		set<RegisterAST::Ptr> rdregs;
		instr->getReadSet(rdregs);
		for (auto i = rdregs.begin(); i != rdregs.end(); ++i)
		{
			RegisterAST::Ptr reg = *i;
			if (!reg->format().compare("RIP"))
			{
				return true;
			}
		}
	}
	return false;
}

bool uses_rip(Block *next_block)
{
	Block::Insns instructions;
	next_block->getInsns(instructions);
	int count = 0;
	for (auto k = instructions.begin(); k != instructions.end(); ++k)
	{
		Instruction::Ptr instr(new Dyninst::InstructionAPI::Instruction(k->second));
		set<RegisterAST::Ptr> rdregs;

		instr->getReadSet(rdregs);
		for (auto i = rdregs.begin(); i != rdregs.end(); ++i)
		{
			RegisterAST::Ptr reg = *i;
			if (!reg->format().compare("RIP"))
			{
				return true;
			}
		}

		count += instr->size();
		if (count >= EXTRA_OW_BYTES)
			break;
	}
	return false;
}

bool uses_fs(Block *next_block)
{
	Block::Insns instructions;
	next_block->getInsns(instructions);
	int count = 0;
	for (auto k = instructions.begin(); k != instructions.end(); ++k)
	{
		Instruction::Ptr instr(new Dyninst::InstructionAPI::Instruction(k->second));
		set<RegisterAST::Ptr> rdregs;

		instr->getReadSet(rdregs);
		for (auto i = rdregs.begin(); i != rdregs.end(); ++i)
		{
			RegisterAST::Ptr reg = *i;
			if (!reg->format().compare("FS"))
			{
				cout << "fs register detected" << endl;
				return true;
			}
		}

		count += instr->size();
		if (count >= EXTRA_OW_BYTES)
			break;
	}
	return false;
}

/* Jump, call or instruction where the destination operand is an immediate */
bool has_incompatible_instruction(Block *next_block)
{
	//print_block(next_block);
	Block::Insns instructions;
	next_block->getInsns(instructions);
	int count = 0;
	for (auto k = instructions.begin(); k != instructions.end(); ++k)
	{
		Instruction::Ptr instr(new Dyninst::InstructionAPI::Instruction(k->second));
		string mnemonic = instr->format();
		// cout << mnemonic.find("call") << endl;
		if (mnemonic.find('j') == 0 or mnemonic.find("call") == 0 or mnemonic.find(",$0x") != string::npos)
		{
			return true;
		}
		count += instr->size();
		if (count >= EXTRA_OW_BYTES)
			break;
	}
	return false;
}

void write_assembly_to_file(vector<Syscall *> *syscall_list, vector<Syscall *> *sc_prev_list, string prog_name)
{
	ofstream asm_file(NEW_ASM_FILE, ios::out | ios::trunc);
	if (!asm_file.is_open())
	{
		cout << "Failed to open file " NEW_ASM_FILE << endl;
		exit(-1);
	}
	/* Add stuff at beginning of file to enable compilation */
	asm_file << "SECTION .ktext\n";
	asm_file << "global dummy_asm_func\n";
	asm_file << "dummy_asm_func:\n";
	asm_file << "\tret \n\n";
	asm_file << get_syscall_asm_func();

	string dump = get_objdump(prog_name);
	map<int, string> *syscall_func_map = get_syscall_func_map();
	//syscall func map: syscall no. -> syscall string

	for (auto i = syscall_list->begin(); i != syscall_list->end(); i++)
	{
		cout << "c1" << endl;
		Syscall *sc = *i;

		string to_write = sc->get_assembly_to_write(dump, syscall_func_map);
		asm_file << to_write;
		cout << to_write << endl;
	}
	for (auto i = sc_prev_list->begin(); i != sc_prev_list->end(); i++)
	{
		Syscall *sc = *i;

		string to_write = sc->get_assembly_to_write_prev(dump, syscall_func_map, sc->get_address(), sc->get_prev_address());
		asm_file << to_write;
		cout << to_write << endl;
	}

	asm_file.close();
	// TODO: write to file within the kernel an extern function
}

void compile_hermitcore()
{
	string cmd1 = "", cmd2 = "", cmd3 = "";
	int ret1, ret2, ret3;

	cmd1 += "make clean -C " + string(HERMITCORE_BUILD_DIR);			  // + " &> /dev/null";
	cmd2 += "make -j$(nproc) -C " + string(HERMITCORE_BUILD_DIR);		  // + " &> /dev/null";
	cmd3 += "make -j$(nproc) install -C " + string(HERMITCORE_BUILD_DIR); // + " &> /dev/null";

	ret1 = system(cmd1.c_str());
	ret2 = system(cmd2.c_str());
	ret3 = system(cmd3.c_str());

	if (ret1 || ret2 || ret3)
	{
		cout << "HermiTux compilation failed\n";
		exit(-1);
	}
	else
		cout << "HermiTux compilation successfull\n";
}

char *copy_file(char *fileName)
{
	string newfilename12 = string(fileName) + "_fast";
	char *newfilename = new char[newfilename12.length() + 1];
	strcpy(newfilename, newfilename12.c_str());
	string cmd = "cp " + string(fileName) + " " + newfilename12;

	if (system(cmd.c_str()))
	{
		cout << "Could not copy file\n";
		exit(-1);
	}
	return newfilename;
}

string get_objdump(string prog_name)
{
	char buf[256];
	string dump;
	string cmd = "objdump -d -M intel --no-show-raw-insn " + prog_name;
	FILE *dump_stream = (FILE *)popen(cmd.c_str(), "r");
	if (!dump_stream)
	{
		perror("Problem with objdump\n");
		exit(-1);
	}
	while (!feof(dump_stream))
	{
		if (fgets(buf, 256, dump_stream) != NULL)
		{
			dump.append(buf);
		}
	}
	pclose(dump_stream);
	return dump;
}

void rewrite_syscalls(vector<Syscall *> *syscall_list, vector<Syscall *> *sc_prev_list, char *fileName)
{
	ElfFile *ef = new ElfFile(fileName);

	uint64_t seg_offset = ef->get_segment_offset();
	uint64_t seg_va = ef->get_segment_va();
	ef->close_file();

	fstream binfile(fileName, fstream::binary | fstream::in | fstream::out);
	if (!binfile.is_open())
	{
		cout << "Unable to open file\n";
		exit(-1);
	}

	int ite = 0;
	for (auto i = syscall_list->begin(); i != syscall_list->end(); i++)
	{
		cout << ++ite << endl;
		Syscall *sc = *i;
		sc->overwrite(binfile, seg_offset, seg_va);
	}
	for (auto i = sc_prev_list->begin(); i != sc_prev_list->end(); i++)
	{
		cout << ++ite << endl;
		Syscall *sc = *i;
		sc->overwrite_prev(binfile, seg_offset, seg_va);
	}

	binfile.close();
}
