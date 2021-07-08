#include "syscall_rewriting.hpp"

Syscall::Syscall(Function *func, Block *block, Instruction::Ptr &instr, uint64_t addr)
{
    this->function = func;
    this->instruction = instr;
    this->address = addr;
    this->sc_block = block;
    this->set_next_block();
    this->num_bytes_to_overwrite = 2;
    this->set_prev_block();
}

Function *Syscall::get_function()
{
    return this->function;
}

Block *Syscall::get_sc_block()
{
    return this->sc_block;
}

Block *Syscall::get_next_block()
{
    return this->next_block;
}

Address Syscall::get_address()
{
    return this->address;
}

Address Syscall::get_prev_address()
{
    return this->write_prev_addr;
}

uint64_t Syscall::get_prev_len()
{
    return this->address - this->write_prev_addr;
}

Instruction::Ptr Syscall::get_instruction()
{
    return this->instruction;
}

void Syscall::set_next_block()
{
    CodeObject *co = this->sc_block->obj();
    CodeRegion *cr = this->sc_block->region();
    this->next_block = co->findBlockByEntry(cr, this->address + 2);
}
void Syscall::set_prev_block()
{
    Block::Insns instructions;
    this->sc_block->getInsns(instructions);
    this->write_prev_addr = -1;
    for (auto k = instructions.begin(); k != instructions.end(); k++)
    {
        Instruction::Ptr instr(new Dyninst::InstructionAPI::Instruction(k->second));
        int addr = k->first;
        if (this->address - addr < 3)
            break;
        this->write_prev_addr = addr;
    }
    cout << "Last addr= " << hex << this->write_prev_addr << endl;
    cout << "len=" << this->address - this->write_prev_addr << endl;
}
vector<int> Syscall::get_possible_sc_nos(void)
{
    vector<Block *> *visited = new vector<Block *>();
    vector<int> *possible_sc_nums = new vector<int>();
    get_value_in_register(this->sc_block, "ax", this->address, visited, possible_sc_nums);
    visited->~vector();
    return *possible_sc_nums;
}

void Syscall::get_value_in_register(Block *curr_block, string reg, Address start_from, vector<Block *> *visited, vector<int> *possible_sc_nums)
{
    visited->push_back(curr_block);

    Block::Insns insns;
    curr_block->getInsns(insns);

    /* Start searching for assignments in instructions in reverse order from the syscall */
    for (auto i = insns.rbegin(); i != insns.rend(); ++i)
    {
        Instruction::Ptr instr(new Dyninst::InstructionAPI::Instruction(i->second));
        Address addr = i->first;

        if (addr > start_from)
        {
            continue;
        }

        if (instruction_assigns_to_register(instr, reg))
        {
            if (instruction_is_mov(instr))
            {
                if (instr->readsMemory())
                {
                    // printf("Memory read!\n");
                    // printf("%lx: %s\n", addr, instr->format().c_str());
                    possible_sc_nums->push_back(-1);
                    return;
                }
                Operand sourceop = instr->getOperand(1);
                if (operand_is_immediate(sourceop))
                {
                    possible_sc_nums->push_back(get_immediate_value(sourceop));
                    return;
                }
                else
                {
                    set<RegisterAST::Ptr> readset;
                    instr->getReadSet(readset);
                    if (readset.size() != 1)
                    {
                        printf("%lx: %s\n", addr, instr->format().c_str());
                        cout << "Read set != 1\n";
                        possible_sc_nums->push_back(-2);
                        return;
                    }
                    string rname = get_size_agnostic_reg_name(*(readset.begin()));
                    get_value_in_register(curr_block, rname, addr, visited, possible_sc_nums);
                    return;
                }
            }

            else if (instruction_is_self_xor(instr))
            {
                possible_sc_nums->push_back(0);
                return;
            }

            else
            {
                printf("Unknown operation affecting value\n");
                printf("%lx: %s\n", addr, instr->format().c_str());
                possible_sc_nums->push_back(-3);
                return;
            }
        }
    }

    /*  No assignment of interest has been made in the current block,
        so we traverse through all preceding blocks in a similar manner  */
    const Block::edgelist &incoming = curr_block->sources();
    for (auto j = incoming.begin(); j != incoming.end(); ++j)
    {
        Block *preceding_block = (*j)->src();
        vector<Function *> pbfuncs;
        preceding_block->getFuncs(pbfuncs);
        bool already_visited = any_of(visited->begin(), visited->end(), [preceding_block](Block *b)
                                      { return preceding_block == b; });
        bool same_func = any_of(pbfuncs.begin(), pbfuncs.end(), [this](Function *f)
                                { return this->function == f; });
        bool empty_list = possible_sc_nums->empty();
        if (!already_visited && (same_func || empty_list))
        {
            get_value_in_register(preceding_block, reg, preceding_block->last(), visited, possible_sc_nums);
        }
    }
}

string Syscall::get_dest_label()
{
    /* Addres will be unique for each syscall */
    char hexaddr[16];
    sprintf(hexaddr, "%lx", this->address);
    return "syscall_" + string(hexaddr) + "_destination";
}

/*  Dyninst cannot recognise negative values, which causes assembler errors.
    This function modifies the instruction string to replace, for example,
    $ffffffff with $-1.
    It may be used in the future for computing RIP dependent values, which
	are currently not part of the syscall list. */
string Syscall::get_modified_instruction(Instruction::Ptr instr)
{
    string new_instr;
    Operation opn = instr->getOperation();
    string curr_instr = instr->format();

    if (!instr->isValid() || !instr->isLegalInsn())
        cout << hex << this->address << ": " << dec << instr->format() << endl;

    if (!opn.format().compare("cmp"))
    {
        vector<Operand> operands;
        instr->getOperands(operands);
        for (auto i = operands.begin(); i != operands.end(); ++i)
        {
            Operand op = *i;
            Result res = op.getValue()->eval();
            if (res.type == s32)
            {
                int32_t newval = res.convert<int32_t>();
                string newop = to_string(newval);
                int pos = curr_instr.find('$') + 1;
                int len = curr_instr.find(',') - pos;
                new_instr = curr_instr.replace(pos, len, to_string(newval));
            }
            else
            {
                new_instr = curr_instr;
            }
        }
    }
    else
    {
        new_instr = curr_instr;
    }
    new_instr += "\n";
    return new_instr;
}

string Syscall::get_objdump_instruction(string objdump, Address addr)
{
    char addr_label[12];
    sprintf(addr_label, "%lx:", addr);
    long label_start = objdump.find(addr_label);
    long insn_start = objdump.find_first_not_of(" \t", label_start + strlen(addr_label));
    long insn_end = objdump.find_first_of("#<\n", insn_start);
    //printf("addr_label = %s; insn_start = %ld; insn_end = %ld\n", addr_label, insn_start, insn_end);
    return objdump.substr(insn_start, insn_end - insn_start);
}

int32_t Syscall::get_displacement()
{
    // get an address to jump to
    FILE *fpipe;
    string cmd = "nm " + string(HERMIT_EXECUTABLE_PATH) + " | grep " + get_dest_label();
    cout << cmd << std::endl;
    ;
    //nm hermitux | grep syscall_xxxxxx_destination
    char line[256]{'\0'};
    uint64_t dest_address;
    int32_t displacement;

    fpipe = popen(cmd.c_str(), "r");
    if (!fpipe)
    {
        perror("Problems with nm pipe");
        exit(-1);
    }

    fgets(line, sizeof(line), fpipe);
    pclose(fpipe);

    if (strlen(line) == 0)
    {
        cout << "Error: Destination label not found\n";
        exit(1);
    }
    dest_address = strtol(line, NULL, 16);

    /* For static binaries the syscall invocation address will always be
	 * superior to the destination as the invocation address is in application
	 * code and the desitination in kernel code. Kernel code is mapped
	 * @0x2000000 and application at 0x4000000. So the displacement is always
	 * negative! */
    displacement = (this->address + JMP_INSTR_SIZE) - dest_address;
    return -displacement;
}

// trim from start
static inline std::string &ltrim(std::string &s)
{
    s.erase(s.begin(), std::find_if(s.begin(), s.end(),
                                    std::not1(std::ptr_fun<int, int>(std::isspace))));
    return s;
}

// trim from end
static inline std::string &rtrim(std::string &s)
{
    s.erase(std::find_if(s.rbegin(), s.rend(),
                         std::not1(std::ptr_fun<int, int>(std::isspace)))
                .base(),
            s.end());
    return s;
}

// trim from both ends
static inline std::string &trim(std::string &s)
{
    return ltrim(rtrim(s));
}

string Syscall::get_assembly_to_write(string objdump, map<int, string> *syscall_func_map)
{
    //cout << objdump << endl;
    //输入objdump是binary的反汇编，syscall_func_map是可支持syscall的序号与内容的映射（由./supported_syscalls.csv得到的）
    string assembly = "";
    assembly += this->get_dest_label() + ":\n";

    // 可能的系统调用号
    vector<int> possible_sc_nos = this->get_possible_sc_nos();
    bool indeterminable_syscall = possible_sc_nos.size() != 1 || possible_sc_nos[0] < 0;

    if (indeterminable_syscall) // 无法确定的syscall
    {
        assembly += "\tcall " SYSCALL_PROLOGUE_FUNC "\n";
    }
    else
    {
        int syscall_no = possible_sc_nos[0];
        auto func_it = syscall_func_map->find(syscall_no);

        if (func_it != syscall_func_map->end()) // 在受支持的syscall里面
        {
            string syscall_func = func_it->second;
            assembly += "\tmov rcx, r10\n"; // 这一句为什么，r10里面保存的是什么

            assembly += "\textern " + syscall_func + "\n";
            assembly += "\tcall " + syscall_func + "\n";
        }
        else
        {
            assembly += "\tcall " SYSCALL_PROLOGUE_FUNC "\n";
        }
    }

    Block::Insns instructions;
    this->next_block->getInsns(instructions);

    for (auto k = instructions.begin(); k != instructions.end(); ++k)
    {
        cout << 1 << endl;
        Instruction::Ptr instr(new Dyninst::InstructionAPI::Instruction(k->second));
        Address addr = k->first;
        auto instr_to_insert = this->get_objdump_instruction(objdump, addr);
        str_replace(instr_to_insert, std::string("PTR "), std::string(""));

        if (instr_to_insert[0] == 'j')
        {
            rtrim(instr_to_insert);
            int last_space = instr_to_insert.rfind(' ');

            instr_to_insert = instr_to_insert.substr(0, last_space) + "0x" + instr_to_insert.substr(last_space + 1);
        }

        assembly += "\t" + instr_to_insert + "\n";
        //assembly += "\t" + get_modified_instruction(instr);
        this->num_bytes_to_overwrite += instr->size();
        cout << this->num_bytes_to_overwrite << endl;
        //add the length after syscall
        if (this->num_bytes_to_overwrite >= 5)
        {
            uint32_t w[2];
            char hexaddr[16];
            uint64_t addr = k->first + instr->size();
            w[1] = 0x0;
            w[0] = addr & 0xffffffff;
            /* Return to user application */
            sprintf(hexaddr, "0x%08x", w[0]);
            assembly += "\tpush " + string(hexaddr) + "\n";
            assembly += "\tret \n";

            break;
        }
    }

    this->sc_block->getInsns(instructions);
    for (auto k = instructions.begin(); k != instructions.end(); ++k)
    {
        Instruction::Ptr instr(new Dyninst::InstructionAPI::Instruction(k->second));
        cout << instr->format() << endl;
    }

    assembly += "\n";
    return assembly;
}

string Syscall::get_assembly_to_write_prev(string objdump, map<int, string> *syscall_func_map, Address sc_addr, Address prev_addr)
{
    string assembly = "";
    assembly += this->get_dest_label() + ":\n";

    vector<int> possible_sc_nos = this->get_possible_sc_nos();
    bool indeterminable_syscall = possible_sc_nos.size() != 1 || possible_sc_nos[0] < 0;
    Block::Insns instructions;
    this->sc_block->getInsns(instructions);

    for (auto k = instructions.begin(); k != instructions.end(); ++k)
    {
        Address addr = k->first;
        if (addr < prev_addr)
            continue;
        if (addr == sc_addr)
            break;
        Instruction::Ptr instr(new Dyninst::InstructionAPI::Instruction(k->second));
        cout << instr->format() << endl;
        auto instr_to_insert = this->get_objdump_instruction(objdump, addr);
        str_replace(instr_to_insert, std::string("PTR "), std::string(""));
        assembly += "\t" + instr_to_insert + "\n";
        //assembly += "\t" + get_modified_instruction(instr);
        this->num_bytes_to_overwrite += instr->size();
    }

    if (indeterminable_syscall)
    {
        assembly += "\tcall " SYSCALL_PROLOGUE_FUNC "\n";
    }
    else
    {
        int syscall_no = possible_sc_nos[0];
        auto func_it = syscall_func_map->find(syscall_no);

        if (func_it != syscall_func_map->end())
        {
            string syscall_func = func_it->second;
            assembly += "\tmov rcx,r10 \n";
            assembly += "\textern " + syscall_func + "\n";
            assembly += "\tcall " + syscall_func + "\n";
        }
        else
        {
            assembly += "\tcall " SYSCALL_PROLOGUE_FUNC "\n";
        }
    }
    uint32_t w[2];
    char hexaddr[16];
    uint64_t addr = sc_addr + 2;
    w[1] = 0x0;
    w[0] = addr & 0xffffffff;

    /* Return to user application */
    sprintf(hexaddr, "0x%08x", w[0]);
    assembly += "\tpush " + string(hexaddr) + "\n";
    assembly += "\tret \n";

    this->sc_block->getInsns(instructions);
    for (auto k = instructions.begin(); k != instructions.end(); ++k)
    {
        Instruction::Ptr instr(new Dyninst::InstructionAPI::Instruction(k->second));
        cout << instr->format() << endl;
    }

    assembly += "\n";
    return assembly;
}

void Syscall::overwrite(fstream &binfile, uint64_t seg_offset, uint64_t seg_va)
{
    int32_t displacement = this->get_displacement();
    printf("disp=%x len=%d\n", displacement, this->num_bytes_to_overwrite);
    uint64_t write_at = seg_offset + (this->address - seg_va);
    char *to_write = new char[this->num_bytes_to_overwrite];
    string padding = "";

    memset(to_write, REL_JMP_OPCODE, 1);
    for (int i = 0; i < 4; i++)
    {
        char foo = (displacement >> (i * 8)) & 0xFF;
        memset(to_write + i + 1, foo, 1);
    }
    memset(to_write + JMP_INSTR_SIZE, 0x90 /* NOP */, this->num_bytes_to_overwrite - JMP_INSTR_SIZE);

    binfile.seekp(write_at);
    binfile.write(to_write, this->num_bytes_to_overwrite);

    // useless
    binfile.write(to_write, JMP_INSTR_SIZE);
}

void Syscall::overwrite_prev(fstream &binfile, uint64_t seg_offset, uint64_t seg_va)
{
    int32_t displacement = this->get_displacement(); // No warning?
    cout << "disp= " << hex << displacement << "\nlen= " << this->get_prev_len() + 2 << endl;
    uint64_t write_at = seg_offset + (this->write_prev_addr - seg_va);
    char *to_write = new char[this->get_prev_len() + 2];
    string padding = "";

    memset(to_write, REL_JMP_OPCODE, 1);
    for (int i = 0; i < 4; i++)
    {
        char foo = (displacement >> (i * 8)) & 0xFF;
        memset(to_write + i + 1, foo, 1);
    }
    memset(to_write + JMP_INSTR_SIZE, 0x90, this->get_prev_len() + 2 - JMP_INSTR_SIZE);

    binfile.seekp(write_at);
    binfile.write(to_write, this->get_prev_len() + 2);
    //binfile.write(to_write, JMP_INSTR_SIZE);
}