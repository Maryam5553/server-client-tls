#include "file_exists.h"

// Returns 1 if the file given in parameter exists, 0 if not.
int file_exists(char *filename)
{
    FILE *file = fopen(filename, "r");
    if (file != NULL)
    {
        fclose(file);
        return 1;
    }
    else
    {
        return 0;
    }
}