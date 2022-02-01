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
#include <pthread.h>

#include "libcommon/lib/arguments.h"
#include "log.h"
#include "zipf.h"
#include "pcap-utils.h"
#include "string-ops.h"

using namespace std;

// Holds arguments information
static arguments args[] = {
// Name                R  B  Def        Help
// Mandatory arguments
{"out",                1, 0, NULL,      "Output filename."},
// Mode Locality:Zipf
{"mode-locality-zipf", 0, 1, NULL,      "(Mode Locality:Zipf) Generate Zipf "
                                        "locality file. (No input file "
                                        "required)"},
{"zipf-count",         0, 0, "10000000","(Mode Locality:Zipf) How many "
                                        "locality items to generate"},
{"zipf-n",             0, 0, "500000",  "(Mode Locality:Zipf) Zipf N "
                                        "parameter."},
{"zipf-alpha",         0, 0, "0.99",    "(Mode Locality:Zipf) Zipf alpha "
                                        "parameter."},
// Mode PCAP
{"mode-pcap",          0, 1, NULL,      "(Mode PCAP) Analyze the PCAP file[s] "
                                        "packet sizes and temporal locality. "
                                        "use \"--out\" for the temporal "
                                        "locality, and \"--out-sizes\" for the"
                                        " packe sizes."},
{"pcap",               0, 0, NULL,      "(Mode PCAP) Input PCAP "
                                        "filenames, separated by semicolon."},
{"out-sizes",          0, 0, NULL,      "(Mode Pcap) if supplied, "
                                        "writes to file VALUE the packet sizes "
                                        "(in bytes)."},
{"out-times",          0, 0, NULL,      "(Mode Pcap) if supplied, "
                                        "writes to file VALUE the packets "
                                        "timestamps (usec)."},
// Mode Locality: Analyze
{"mode-locality-analyze",0,1,NULL,      "(Mode Locality:Analyze) "
                                        "Use a sliding window to analyze the "
                                        "temporal locality within a locality "
                                        "file"},
{"window",             0,0,  "3000000", "(Mode Locality:Analyze) window size"},
{"step",               0,0,  "800000",  "(Mode Locality:Analyze) step size"},
{NULL,                 0, 0, NULL,      "Analyzes PCAP files. Extracts "
                                        "5-tuples locality, packet sizes, and "
                                        "inter-packet delays. Zipf locality "
                                        "support."}
};

/**
 * @brief Prints progres to the screen
 * @param message Message to show
 * @param current Current iteration
 * @param size Total iterations (or 0 - to show complete message)
 */
void
print_progress(const char* message, size_t current, size_t size)
{
    if ( (size ==0) || (current < 0) ) {
        MESSAGE("\r%s... Done   \n", message);
    } else {
        int checkpoint = size < 100 ? 1 : size/100;
        if (current%checkpoint==0) {
            MESSAGE("\r%s... (%lu%%)", message, current/checkpoint);
        }
    }
}

/**
 * @brief Generates a vector of 'n' integers with Zipf(N,alpha) distribution.
 */
vector<long>
generate_zipf_locality()
{

    int n = ARG_INTEGER(args, "zipf-count", 0);
    int N = ARG_INTEGER(args, "zipf-n", 0);
    double alpha = ARG_DOUBLE(args, "zipf-alpha", 0);

    MESSAGE("Generating Zipf locality with N=%d and alpha=%lf\n", n, alpha);
    vector<long> output;

    for (int i=0; i<n; ++i) {
        output.push_back(zipf(alpha, N));
        print_progress("Generating zipf distribution", i, n);
    }

    print_progress("Generating zipf distribution", 0, 0);
    return output;
}

/**
 * @brief Analyzes the locality percent for 3% percent of the traffic
 */
void
analyze_locality_percent(vector<long>& locality)
{
    const double traffic_percent = 0.03;
    int N = ARG_INTEGER(args, "zipf-n", 0);
    int max_bound = N * traffic_percent;
    double counter = 0;
    for (auto x : locality) {
        if (x<=max_bound) {
            counter++;
        }
    }
    MESSAGE("%.0lf%% most frequent flows hold %.0lf%% of the traffic "
        "(%d available flows, %ld traffic size)\n",
        traffic_percent*100,
        counter/locality.size()*100,
        N,
        locality.size());
}

/**
 * @brief Writes a vector of integers to file
 */
void
write_integers_to_file(const char* filename, const vector<long>& vec)
{
    std::ofstream file_out(filename, ios_base::out | ios_base::trunc);
    if (!file_out.is_open()) {
        throw errorf("Cannot write to file \"%s\"", filename);
    }
    for (auto it : vec) {
        file_out << it << std::endl;
    }
    file_out.close();
}


/**
 * @brief Slide a window over the locality file, return a list of locality reuse
 * factor (0-1)
 * @param filename Locality filename
 * @param window Size of sliding window
 * @param step Size of analysis
 * @param os Stream to write results into
 */
void
parse_locality_file(const char* filename,
                    int window,
                    int step,
                    std::ostream& os)
{

    std::ifstream file_in (filename);

    if (!file_in.is_open()) {
        throw errorf("Cannot read file \"%s\"", filename);
    }

    vector<int> sliding_window(window);
    multiset<int> values;

    int i = 0;
    int j = 0;
    int reuse = 0;
    string line;

    while (getline(file_in, line)) {
        int current = atoi(line.c_str());

        if (values.find(current) != values.end()) {
            reuse++;
        }

        /* Update the values and the sliding window */
        values.erase(sliding_window[i]);
        values.insert(current);
        sliding_window[i] = current;
        i++;
        j++;

        if (i == window) {
            i = 0;
        }
        if (j == step) {
            os << (float)reuse / window << std::endl;
            reuse = 0;
            j = 0;
        }
    }
}

/**
 * @brief Mode locality Zipf
 */
void
mode_locality_zipf()
{

    MESSAGE("Mode locality:zipf enabled\n");

    const char* out_filename = ARG_STRING(args, "out", NULL);
    vector<long> locality = generate_zipf_locality();
    analyze_locality_percent(locality);

    // Write to file
    MESSAGE("Writing locality to file \"%s\"...\n", out_filename);
    write_integers_to_file(out_filename, locality);
}

/**
 * @brief Mode locality PCAP file
 */
void
mode_pcap()
{

    const char* locality_filename = ARG_STRING(args, "out", NULL);
    const char* sizes_filename = ARG_STRING(args, "out-sizes", NULL);
    const char* times_filename = ARG_STRING(args, "out-times", NULL);

    string pcap_files = ARG_STRING(args, "pcap", NULL);
    if (pcap_files.size() == 0) {
        throw errorf("Mode trace requires pcap argument.");
    }

    PcapReader pcap_reader;

    // Split by commas
    StringOperations<string> str_ops;
    std::vector<string> file_names = str_ops.split(pcap_files,
            ";", [](const string& s) {return s;});

    for (auto& f : file_names) {
        size_t start_size = pcap_reader.get_locality().size();

        MESSAGE("Parsing PCAP file \"%s\"... \n", f.c_str());
        pcap_reader.read(f.c_str(), -1);

        size_t end_size = pcap_reader.get_locality().size();
        MESSAGE("Extracted %lu values \n", end_size-start_size);
    }

    MESSAGE("Total values: %lu \n", pcap_reader.get_locality().size());

    // Write output
    if (locality_filename) {
        MESSAGE("Writing locality to file \"%s\"...\n", locality_filename);
        write_integers_to_file(locality_filename, pcap_reader.get_locality());
    }
    if (sizes_filename) {
        MESSAGE("Writing size to file \"%s\"...\n", sizes_filename);
        write_integers_to_file(sizes_filename, pcap_reader.get_sizes());
    }
    if (times_filename) {
        MESSAGE("Writing timestamps to file \"%s\"...\n", times_filename);
        write_integers_to_file(times_filename, pcap_reader.get_timestamps());
    }
}

/**
 * @brief Analyze locality file
 */

void
mode_locality_analyze()
{

    const char* out_filename = ARG_STRING(args, "out", NULL);
    const char* locality_filename = ARG_STRING(args, "locality", NULL);
    std::ofstream os;

    if (locality_filename == NULL ){
        throw errorf("Cannot open locality file.");
    }

    int window = ARG_INTEGER(args, "window", 3000000);
    int step = ARG_INTEGER(args, "step", 800000);

    MESSAGE("Analyzing locality file \"%s\" with window %d and step %d...\n",
               locality_filename,
               window,
               step);

    os.open(out_filename);

    parse_locality_file(locality_filename, window, step, os);
}

/**
 * @brief Application entry point
 */
int
main(int argc, char** argv)
{

    LOG_SET_STDOUT;

    // Parse arguments
    arg_parse(argc, argv, args);

    try {
        // Act according to mode
        if (ARG_BOOL(args, "mode-locality-zipf", 0)) {
            mode_locality_zipf();
        } else if (ARG_BOOL(args, "mode-pcap", 0)) {
            mode_pcap();
        } else if (ARG_BOOL(args, "mode-locality-analyze", 0)) {
            mode_locality_analyze();
        } else {
            throw errorf("No mode was specified");
        }
    } catch (std::exception & e) {
        MESSAGE("Error: %s\n", e.what());
        return 1;
    }

    return 0;
}

