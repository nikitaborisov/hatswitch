#ifndef STRINGTOKENIZER_H_
#define STRINGTOKENIZER_H_

#include <sys/types.h>
#include <unistd.h>
#include <string>
#include <vector>

using namespace std;

class StringTokenizer
{
private:
	string str, delim;
	vector<string> tokens;

public:
	StringTokenizer(const string& s, const string& d);
	int countTokens() const;
	bool hasMoreTokens() const;
	string nextToken();
	string toString() const;
};

#endif /* STRINGTOKENIZER_H_ */
