#include <list>
#include <fstream>
#include <vector>
#include <queue>
#include <set>
#include <map>
#include <atomic>
#include <iostream>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>

#include "arguments.h"
#include "log.h"

static arguments args[] = {
/* Name               R  B  Def        Help */
{"in",                1, 0, NULL,      "Output filename."},
{"window",            0, 0, "10",      "Window size."},
{NULL,                0, 0, NULL,      "Analyzes locality files and calcs the "
                                       "CDF of temporal locality within the "
                                       "given window size. Prints to stdout "
                                       "in the following format: "
                                       " X (recurrent within window) Y "
                                       " (CDF value, in [0,1]), where X=0 is "
                                       "the probability of getting new "
                                       "element, X=1 is the probablity to get "
                                       "the most recently used element, X=2 "
                                       "the 2nd most recently used element, "
                                       "and so forth."}
};

/**
 * @brief Reads integers from "fname" into a vector
 */
static std::vector<long>
read_integers_from_file(const char *fname)
{
    std::vector<long> output;
    std::ifstream is;
    std::string line;
    long linenum;

    is.open(fname);
    if (is.bad()) {
        std::cerr << "Cannot open '" << fname << "' for reading" << std::endl;
        exit(EXIT_FAILURE);
    }

    std::cout << "Calculating nubmer of lines in '" << fname << "'..."
              << std::endl;
    linenum = 0;
    while (std::getline(is, line)) {
        linenum++;
    }

    std::cout << "Reading data from '" << fname << "'..." << std::endl;

    is.clear();
    is.seekg(0);
    output.reserve(linenum);

    while (std::getline(is, line)) {
        output.push_back(atol(line.c_str()));
    }

    return output;
}

/**
 * @brief Checks if "value" is already present in "window". Updates the
 * values in "window" s.t element[0] is the most recently seen and element[N-1]
 * is the least recently seen (within the window size). Returns the index
 * of the seen element, or -1 if it was not seen before.
 */
static int
push_value_to_window(std::vector<long> &window, long value)
{
    int idx = -1, start;

    for (size_t i=0; i<window.size(); ++i) {
        if (window[i] == value) {
            idx = i;
            break;
        }
    }

    start = idx == -1 ? window.size() - 1 : idx;

    for (int i=start; i>0; --i) {
        window[i] = window[i-1];
    }
    window[0] = value;
    return idx;
}

static void
analyze(const std::vector<long> nums, int window_size)
{
    std::vector<long> window;
    std::vector<long> encounter;
    long total;
    int idx;

    /* Reset window with invalid values */
    window.resize(window_size);
    encounter.resize(window_size+1);
    for (int i=0; i<window_size; ++i) {
        window[i] = -1;
    }
    for (int i=0; i<window_size+1; ++i) {
        encounter[i] = 0;
    }

    total = 0;
    for (size_t i=0; i<nums.size(); ++i) {
        idx = push_value_to_window(window, nums[i]);
        encounter[idx+1]++;
        total++;
    }

    std::cout << "Results: index CDF" << std::endl;
    double current = 0;
    for (size_t i=0; i<encounter.size(); ++i) {
        current += encounter[i] * 1.0 / total;
        std::cout << i << " "
                  << current
                  << std::endl;
    }
}

int
main(int argc, char** argv)
{
    std::vector<long> nums;
    const char *fname;
    int window;

    LOG_SET_STDOUT;
    arg_parse(argc, argv, args);

    fname = ARG_STRING(args, "in", NULL);
    window = ARG_INTEGER(args, "window", 10);
    nums = read_integers_from_file(fname);
    analyze(nums, window);

    return 0;
}

