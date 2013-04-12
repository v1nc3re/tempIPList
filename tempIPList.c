/*  Searches whitelist CSV and old PCAPs for IP
 *
 *  prints out   Found: IP, desription and where pcap is if there is one.
 *    Grab list of IPs to search / cli IPs -> put into list
 *    Read through CSV  -> grab line, check for IP in our list
 *    if it is then 
*/

#include "histSearch.h"


int main(int argc, char *argv[])
{
    int fflag = 0;
    int wflag = 0;
    char *fvalue = NULL;
    char *wvalue = NULL;
    int c, index;
    FILE *whitelist = NULL;
    FILE *iplist = NULL;

    opterr = 0;

    while ((c = getopt (argc, argv, "f:hw:")) != -1)
    {
        switch (c)
        {
            case 'f':
                    fflag = 1;
                    fvalue = optarg;        
                    break;

            case 'h':
                    usage();
                    break;

            case 'w':
                    wflag = 1;
                    wvalue = optarg;
                    break;

            case '?':
                    if (optopt == 'f' || optopt == 'w')
                        fprintf (stderr, "Option -%c requires a filename\n", optopt);

            default:
                   printf("Invalid flag\n");
                   usage();
                   break;
        }
    }

    if (wflag)
    {
        whitelist = fopen(wvalue, "r");
        if (whitelist == NULL)
        {
            printf("Whitelist does not exist\n");
            usage();
        }
    }
    else
    {
        usage();
    }
    
    if (fflag)
    {
        iplist = fopen(fvalue, "r");

        if (iplist != NULL)
        {    
            char line[16];
            char *nl;

            while (fgets(line, sizeof(line), iplist))
            {
                //strips off the \n that fgets grabs
                if ((nl = strchr(line, '\n')))
                {
                    *nl=0;
                }

                if (ipCheck(line))
                {
                    whitelist_check(whitelist,line);
                }
            }
            fclose(iplist);
        }
        else
        {
            printf("IP list does not exist\n");
            usage();
        }
    }


    for (index = optind; index < argc; index++)
    {    
        if (ipCheck(argv[index]))
        {
            whitelist_check(whitelist, argv[index]);        
        }
    }
    
    if (whitelist != NULL)
    {
        fclose(whitelist);
    }

    return 0;
}


void usage(void)
{
    printf("\nUsage: histSearch [-f] [-w] [-h] [IP address]\n");
    printf("-w    Required whitelist file\n");
    printf("-f    Optional IP list file\n");
    printf("\n Example:  ./histSearch -w wl.csv -f ipFile 1.1.1.1 2.2.2.2\n");
    printf("\n **Hurray efficiency!** \n");
    exit(8);
}

int ipCheck(char *ipaddr)
{
    int len = 0;
    char tail[16] = {0};
    unsigned int d[4];
    int i, c;

    //check if length is appropriate for string
    len = strlen(ipaddr);

    if (len < 7 || len > 15)
    {
        return 0;
    }
    
    //check if it has 4 octets of up to 3 numbers each
    c = sscanf(ipaddr, "%3u.%3u.%3u.%3u%s", &d[0], &d[1], &d[2], &d[3], tail);
    
    if (c != 4 || tail[0])
    {
        return 0;
    } 
    
    //check if first not 0 and  each number is lower than 255
    for (i = 0; i < 4; i++)
    {
        if ((i == 0 && d[i] == 0) || d[i] > 255)
        {
            return 0;
        }
     }
    
    return 1; // if all the checks are passed return TRUE!    
}

void whitelist_check(FILE *wl, char *ip)
{
    fpos_t position;
    char *parse = NULL;
    char line[4000];                
    char *pLine[3] = {0};    
    int i=0;
    char *nl;
    
    fgetpos(wl, &position); //grab start pos

    while (fgets(line, sizeof(line), wl))
    {
        if ((nl = strchr(line, '\n')))
        {
            *nl=0;
        }

        i=0;
        parse = strtok(line, ",");

        while (parse != NULL)
        {
            pLine[i] = malloc(strlen(parse) + 1);
            strcpy(pLine[i], parse);
            parse = strtok(NULL, ",");
            i++;
        }
        
        if (strncmp(pLine[1], ip,15) == 0)
        {
            printf("\nIP: %s\n%s\n\n",pLine[1],pLine[3]);
        }
    }
    
    //reset everything properly
    fsetpos(wl, &position); //put pos back to start
    for (i=0; i < 4; i++)
    {
        free(pLine[i]);
    }
}