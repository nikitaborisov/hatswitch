#include <sys/types.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include "StringTokenizer.h"
#include "R.h"

using namespace std;

double calculateCorrelation(const double* x, const double* y, int n)
{
	if(n < 2)
	{
		fprintf(stderr, "[calculateCorrelation] Insufficient data. Number of elements at each data set must be >= 2.\n");
		return -2.0;
	}

	char buffer[MAX_BUFFER_SIZE];
	string strX = "", strY = "";

	snprintf(buffer, MAX_BUFFER_SIZE - 1, "%f,%f", x[0], x[1]);
	strX = buffer;

	snprintf(buffer, MAX_BUFFER_SIZE - 1, "%f,%f", y[0], y[1]);
	strY = buffer;

	for(int i = 2; i < n; i++)
	{
		snprintf(buffer, MAX_BUFFER_SIZE - 1, ",%f", x[i]);
		strX += buffer;

		snprintf(buffer, MAX_BUFFER_SIZE - 1, ",%f", y[i]);
		strY += buffer;
	}

	char inputFileName[] = "/tmp/Rtemp.XXXXXX"; // template for new file name
	int fd = mkstemp(inputFileName);
	if (fd == -1)
	{
		fprintf(stderr, "[calculateCorrelation] Error in creating temporary input file %s.\n", inputFileName);
		return -2.0;
	}

	close(fd);

	FILE* fpRin = fopen(inputFileName, "w");
	if(fpRin == NULL)
	{
		fprintf(stderr, "[calculateCorrelation] Error in accessing temporary input file %s.\n", inputFileName);
		unlink(inputFileName);
		return -2.0;
	}

	fprintf(fpRin, "x<-c(%s)\n", strX.c_str());
	fprintf(fpRin, "y<-c(%s)\n", strY.c_str());
	fprintf(fpRin, "cor(x,y)\n");

	fclose(fpRin);

	string strOutputFileName = inputFileName;
	strOutputFileName += ".Rout";

	string strCommand = "R CMD BATCH --no-save --no-restore --quiet --slave --no-timing ";
	strCommand += inputFileName;
	strCommand += " ";
	strCommand += strOutputFileName;

	int res = system(strCommand.c_str());
	if(res == -1)
	{
		fprintf(stderr, "[calculateCorrelation] Error in executing command %s.\n", strCommand.c_str());
		unlink(inputFileName);
		unlink(strOutputFileName.c_str());
		return -2.0;
	}

	FILE* fpRout = fopen(strOutputFileName.c_str(), "r");
	if(fpRout == NULL)
	{
		fprintf(stderr, "[calculateCorrelation] Cannot open output file %s.\n", strOutputFileName.c_str());
		unlink(inputFileName);
		unlink(strOutputFileName.c_str());
		return -2.0;
	}

	double corrVal = -2.0;

	while(!feof(fpRout))
	{
		char* s;

		do
		{
			s = fgets(buffer, MAX_BUFFER_SIZE, fpRout);
			if(s == NULL)
			{
				break;
			}
		}while(strstr(buffer, "[1]") != buffer);

		if(s == NULL)
		{
			if(feof(fpRout) != 0)
			{
				fprintf(stderr, "[calculateCorrelation] Incomplete data at output file %s.\n", strOutputFileName.c_str());
				corrVal = -2.0;
				break;
			}
			else if(ferror(fpRout) != 0)
			{
				fprintf(stderr, "[calculateCorrelation] Error in reading output file %s.\n", strOutputFileName.c_str());
				corrVal = -2.0;
				break;
			}
			else
			{
				fprintf(stderr, "[calculateCorrelation] Unknown error in reading output file %s.\n", strOutputFileName.c_str());
				corrVal = -2.0;
				break;
			}
		}

		StringTokenizer st(buffer, " \r\n");
		if(st.countTokens() != 2)
		{
			fprintf(stderr, "[calculateCorrelation] Unsupported format in output file %s.\n", strOutputFileName.c_str());
			corrVal = -2.0;
			break;
		}

		st.nextToken(); // ignore the first token ("[1]")
		corrVal = atof(st.nextToken().c_str());

		break;
	}

	fclose(fpRout);

	unlink(inputFileName);
	unlink(strOutputFileName.c_str());

	return corrVal;
}
