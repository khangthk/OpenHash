#pragma once
#include "openhash.h"

class Setting
{
public:
	static void saveHash(const Hash hash, const bool value);
	static bool getHash(const Hash hash);
};
