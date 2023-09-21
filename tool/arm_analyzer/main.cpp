//
// Created by orzgg on 2020-09-11.
//

#include <capstone/capstone.h>
#include <fmt/format.h>
#include "json.hpp"

#include <unordered_set>
#include <string_view>
#include <string>
#include <fstream>

using namespace std;
using namespace nlohmann;

unordered_set<string> v4ALU = {
	"mov", "movs", "mvn", "mvns", "and", "ands", "eor", "eors",
	"sub", "subs", "rsb", "rsbs", "add", "adds", "adc", "adcs",
	"sbc", "sbcs", "rsc", "rscs", "orr", "orrs", "bic", "bics",
	"cmp", "cmn", "teq", "tst"
};

unordered_set<string> v4PSR = {
	"mrs", "msr"
};

unordered_set<string> v4Branch = {
	"b", "bl", "bx"
};

unordered_set<string> v4MUL = {
	"mul", "mla", "muls", "mlas"
};

unordered_set<string> v4MULL = {
	"umull", "umlal", "smull", "smlal",
	"umulls", "umlals", "smulls", "smlals"
};

unordered_set<string> v4Transfer = {
	"ldr", "ldrb", "ldrt", "ldrbt",
	"str", "strb", "strt", "strbt"
};

unordered_set<string> v4HalfTransfer = {
	"ldrh", "ldrsh", "ldrsb", "strh"
};

unordered_set<string> v4TransBlock = {
	"ldm", "ldmib", "ldmia", "ldmdb", "ldmda", "stm", "stmib", "stmia",
	"stmdb", "stmda"
};

unordered_set<string> v4Swp = {
	"swp", "swpb"
};

unordered_set<string> v4Interrupt = {
	"svc"
};

unordered_set<string> v4Shift = {
	"lsl", "lsr", "asr", "ror", "rrx",
	"lsls", "lsrs", "asrs", "rors"
};

#define CODE "\x55\x48\x8b\x05"

struct Capstone {
  Capstone() {
	if (cs_open(CS_ARCH_ARM, CS_MODE_ARM, &handle) != CS_ERR_OK)
	  exit(0);
  }

  bool Disassemble(uint32_t code) {
	if (insn != nullptr) {
	  cs_free(insn, count);
	  insn = nullptr;
	} // if

	count = cs_disasm(handle, reinterpret_cast<const uint8_t *>(&code), 4, 0, 0, &insn);
	return count > 0;
  }

  const char *GetMnemonic() { return insn[0].mnemonic; }

  ~Capstone() {
	cs_free(insn, count);
	cs_close(&handle);
  }

  csh handle;
  cs_insn *insn = nullptr;
  size_t count;
};

string JoinValues(const nlohmann::json &j) {
  string result = "";
  for (const auto &item : j.items()) {
	result += item.value();
  } // fo
  return result;
}

json ALU(uint32_t i, const string_view &mnemonic) {
  json attr = json::object();
  attr["Flags"] = json::array();
  attr["TypeName"] = "alu";
  attr["TypeCode"] = 0;

  if (i & (1 << 20))
	attr["Flags"].push_back("s");

  if (i & (1 << 25)) {
	attr["Flags"].push_back("i");
	attr["Signature"] = fmt::format(
		"{}{}", mnemonic,
		JoinValues(attr["Flags"]));
  } // if
  else {
	attr["Shift"]["Amount"] = (i & (1 << 4) ? "Rs" : "Imm");
	switch ((i & (0b11 << 5)) >> 5) {
	case 0x0 :attr["Shift"]["Type"] = "LSL";
	  break;
	case 0x1:attr["Shift"]["Type"] = "LSR";
	  break;
	case 0x2:attr["Shift"]["Type"] = "ASR";
	  break;
	case 0x3 :attr["Shift"]["Type"] = "ROR";
	  break;
	}

	attr["Signature"] = fmt::format(
		"{}{}_{}",
		mnemonic,
		JoinValues(attr["Flags"]),
		fmt::format("{}{}",
					JoinValues(attr["Shift"]["Amount"]),
					JoinValues(attr["Shift"]["Type"])
		));
  } // else

  return attr;
}

json Branch(uint32_t i, const string_view &mnemonic) {
  json attr = json::object();
  attr["Flags"] = json::array();
  attr["TypeName"] = "branch";

  if (i & (1 << 27) && i & (1 << 24))
	attr["Flags"].push_back("l");

  attr["Signature"] = fmt::format("{}{}", mnemonic, JoinValues(attr["Flags"]));
  return attr;
}

json PSR(uint32_t i, const string_view &mnemonic) {
  json attr = json::object();
  attr["Flags"] = json::array();
  attr["TypeName"] = "psr";
  attr["TypeCode"] = 0;

  if (i & (1 << 22))
	attr["Flags"].push_back("p");

  if (mnemonic == "msr") {
	if (i & (1 << 25))
	  attr["OperandType"] = "Imm";
	else
	  attr["OperandType"] = "Rm";
	attr["Signature"] = fmt::format(
		"{}{}_{}",
		mnemonic,
		JoinValues(attr["Flags"]),
		attr["OperandType"]);
  } // if
  else
	attr["Signature"] = fmt::format("{}{}", mnemonic, JoinValues(attr["Flags"]));

  return attr;
}

json MUL(uint32_t i, const string_view &mnemonic) {
  json attr = json::object();
  attr["Flags"] = json::array();
  attr["TypeName"] = "mul";
  attr["TypeCode"] = 1;
  if (i & (1 << 21))
	attr["Flags"].push_back("a");
  if (i & (1 << 20))
	attr["Flags"].push_back("s");

  attr["Signature"] = fmt::format(
	  "{}{}",
	  mnemonic, JoinValues(attr["Flags"]));
  return attr;
}

json MULL(uint32_t i, const string_view &mnemonic) {
  json attr = json::object();
  attr["Flags"] = json::array();
  attr["TypeName"] = "mull";
  attr["TypeCode"] = 2;

  if (i & (1 << 22))
	attr["Flags"].push_back("u");
  if (i & (1 << 21))
	attr["Flags"].push_back("a");
  if (i & (1 << 20))
	attr["Flags"].push_back("s");

  attr["Signature"] = fmt::format(
	  "{}{}",
	  mnemonic, JoinValues(attr["Flags"]));
  return attr;
}

json Transfer(uint32_t i, const string_view &mnemonic) {
  json attr = json::object();
  attr["Flags"] = json::array();
  attr["TypeName"] = "transfer";
  attr["TypeCode"] = 6;

  if (i & (1 << 20))
	attr["Flags"].push_back("l");
  if (i & (1 << 24))
	attr["Flags"].push_back("p");
  if (i & (1 << 23))
	attr["Flags"].push_back("u");
  if (i & (1 << 22))
	attr["Flags"].push_back("b");
  if (i & (1 << 21))
	attr["Flags"].push_back("w");
  if (i & (1 << 25)) {
	attr["Flags"].push_back("i");
	attr["Shift"]["Amount"] = "Imm";
	switch ((i & (0b11 << 5)) >> 5) {
	case 0x0 :attr["Shift"]["Type"] = "LSL";
	  break;
	case 0x1:attr["Shift"]["Type"] = "LSR";
	  break;
	case 0x2:attr["Shift"]["Type"] = "ASR";
	  break;
	case 0x3 :attr["Shift"]["Type"] = "ROR";
	  break;
	} // switch

	attr["Signature"] = fmt::format(
		"{}{}_{}",
		mnemonic,
		JoinValues(attr["Flags"]),
		fmt::format("{}{}",
					JoinValues(attr["Shift"]["Amount"]),
					JoinValues(attr["Shift"]["Type"])
		));
  } // if
  else
	attr["Signature"] = fmt::format("{}{}", mnemonic, JoinValues(attr["Flags"]));

  return attr;
}

json HalfTransfer(uint32_t i, const string_view &mnemonic) {
  json attr = json::object();
  attr["Flags"] = json::array();
  attr["TypeName"] = "half_transfer";
  attr["TypeCode"] = 5;

  if (i & (1 << 24))
	attr["Flags"].push_back("p");
  if (i & (1 << 23))
	attr["Flags"].push_back("u");
  if (i & (1 << 21))
	attr["Flags"].push_back("w");
  if (i & (1 << 20))
	attr["Flags"].push_back("l");
  if (i & (1 << 6))
	attr["Flags"].push_back("s");
  if (i & (1 << 5))
	attr["Flags"].push_back("h");

  if (i & (1 << 22))
	attr["OffsetType"] = "Imm";
  else
	attr["OffsetType"] = "Rm";

  attr["Signature"] = fmt::format("{}{}_{}",
								  mnemonic,
								  JoinValues(attr["Flags"]),
								  JoinValues(attr["OffsetType"])
  );

  return attr;
}

json TransBlock(uint32_t i, const string_view &mnemonic) {
  json attr = json::object();
  attr["Flags"] = json::array();
  attr["TypeName"] = "block_transfer";
  attr["TypeCode"] = 8;

  if (i & (1 << 24))
	attr["Flags"].push_back("p");
  if (i & (1 << 23))
	attr["Flags"].push_back("u");
  if (i & (1 << 22))
	attr["Flags"].push_back("s");
  if (i & (1 << 21))
	attr["Flags"].push_back("w");
  if (i & (1 << 20))
	attr["Flags"].push_back("l");

  attr["Signature"] = fmt::format("{}{}", mnemonic, JoinValues(attr["Flags"]));
  return attr;
}

void printProgressBar(uint64_t iteration, uint64_t total, const char *prefix, const char *suffix, int length = 50) {
  string percent = fmt::format("{0:.1f}", 100 * (iteration / float(total)));
  int filledLength = length * iteration / total;
  string bar = fmt::format("{:█^{}}{:-^{}}", "", filledLength, "", length - filledLength);
  fmt::print(stderr, "{} |{}| {}% {}\r", prefix, bar, percent, suffix);
} // printProgressBar()

int main(int argc, char *argv[]) {
  int num = 0;
  Capstone cs;
  json records = json::array();
  unordered_map<int, string> check;
  // unordered_set<int> debug {433,434,435,436,437,438,439,440,442,444,446} ;
  uint64_t start = 0xe0000000, end = 0xefffffff;
  printProgressBar(0, end - start, "Progress(0xe0000000,0):", "Complete");
  for (uint32_t i = start; i <= end; ++i) {
	if (cs.Disassemble(i)) {
	  uint32_t hashResult = ((i & 0x0ff00000) >> 16) | ((i & 0xf0) >> 4);
	  string_view mnemonic(cs.GetMnemonic());
	  json record;

	  record["Hash"] = hashResult;
	  if (v4ALU.contains(cs.GetMnemonic())) {
		record["Attribute"] = ALU(i, mnemonic.substr(0, 3));
	  } // if
	  else if (v4PSR.contains(cs.GetMnemonic())) {
		record["Attribute"] = PSR(i, mnemonic);
	  } // else if
	  else if (v4Branch.contains(cs.GetMnemonic())) {
		if (mnemonic == "bx") {
		  record["Attribute"] = Branch(i, "bx");
		  record["Attribute"]["TypeCode"] = 4;
		} // if
		else {
		  record["Attribute"] = Branch(i, "b");
		  record["Attribute"]["TypeCode"] = 9;
		} // else
	  } // else if
	  else if (v4MUL.contains(cs.GetMnemonic())) {
		record["Attribute"] = MUL(i, mnemonic.substr(0, 3));
	  } // else if
	  else if (v4MULL.contains(cs.GetMnemonic())) {
		record["Attribute"] = MULL(i, mnemonic.substr(1, 4));
	  } // else if
	  else if (v4Transfer.contains(cs.GetMnemonic())) {
		record["Attribute"] = Transfer(i, mnemonic.substr(0, 3));
	  } // else if
	  else if (v4HalfTransfer.contains(cs.GetMnemonic())) {
		record["Attribute"] = HalfTransfer(i, mnemonic.substr(0, 3));
	  } // else if
	  else if (v4TransBlock.contains(cs.GetMnemonic())) {
		record["Attribute"] = TransBlock(i, mnemonic.substr(0, 3));
	  } // else if
	  else if (v4Swp.contains(cs.GetMnemonic())) {
		json attr = json::object();
		attr["Flags"] = json::array();
		attr["TypeName"] = "swap";
		attr["TypeCode"] = 3;

		if (i & (1 << 22))
		  attr["Flags"].push_back("b");
		attr["Signature"] = fmt::format("{}{}", mnemonic.substr(0, 3), JoinValues(attr["Flags"]));
		record["Attribute"] = attr;
	  } // else if
	  else if (string(cs.GetMnemonic()) == "svc") {
		json attr = json::object();
		attr["Flags"] = json::array();
		attr["TypeName"] = "interrupt";
		attr["TypeCode"] = 13;
		attr["Signature"] = "svc";
		record["Attribute"] = attr;
	  } // else if
	  else if (v4Shift.contains(cs.GetMnemonic())) {
		record["Attribute"] = ALU(i, "mov");
	  } // else if

	  if (record.contains("Attribute")) {
		const string &thisSignature = record["Attribute"]["Signature"];
		if (check.contains(hashResult)) {
		  if (check[hashResult] != thisSignature) {
			fmt::print(stderr, "{} collide with {}\n",
					   thisSignature,
					   check[hashResult]
			);

			exit(-1);
		  } // if
		} // if
		else {
		  check[hashResult] = thisSignature;
		  records.push_back(record);
		  ++num;
		} // else
	  } // if
	} // if

	if (((i - start) % 0x100000) == 0)
	  printProgressBar(i - start, end - start,
					   fmt::format("Progress({:#x},{}):", i, num).c_str(), "Complete");
  } // for

  printProgressBar(end, end,
				   fmt::format("Progress({:#x},{}):", end, num).c_str(), "Complete");

  fstream out(argv[1], fstream::out);
  out << records.dump(2);
  out.close();
  fmt::print("\n");
}