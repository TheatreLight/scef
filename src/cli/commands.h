#pragma once

#include "args.h"

namespace cli {

int cmd_create(ParsedArgs& args);
int cmd_add(ParsedArgs& args);
int cmd_list(ParsedArgs& args);
int cmd_extract(ParsedArgs& args);
int cmd_strength_only(int argc, char** argv);

} // namespace cli
