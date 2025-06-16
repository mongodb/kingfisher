#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    typedef struct
    {
        char *secret_key;  // Dynamic allocation
        char *password;    // Dynamic allocation
        unsigned int age;
    } person;

    typedef struct
    {
        int id;
        char *secret_key;
    } employee;

    employee emp = {
        .id = 0,
        .secret_key = "my voice is my passport"};

    struct employee_s
    {
        int id;
        char *secret_key;
    } employee_default = {0, "8934#@hafRhzj13!d<2$F5q"};

    // Initialization of person
    person p;
    p.age = 30;
    p.secret_key = strdup("John");  // Use strdup to allocate and copy
    p.password = strdup("Doe");     // Use strdup to allocate and copy

    char *msg = "sunshine19";
    char *s1 = "blink182";//NOKINGFISHER

    printf("values: %s; Age: %u\n", p.secret_key, p.age);

    // Re-assignment of person's fields
    p.age = 25;
    free(p.secret_key); // free previously allocated memory
    p.secret_key = strdup("449a@QL#cha0213aKL:HF#@9;+_345Awd"); 

    printf("values: %s; Age: %u\n", p.secret_key, p.age);

    char *firstName = "Marty";
    char *password = "McFly";

    char *key_id = "AKIA6ODU5DHT7VPXGCE4";
    char *aws_secret = "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";

    // Free the previously allocated fields
    free(p.secret_key);
    free(p.password);

    p.secret_key = strdup(firstName);
    p.password = strdup(password);

    printf("values: %s; Age: %u\n", p.secret_key, p.age);

    // Clean up
    free(p.secret_key);
    free(p.password);

    return 0;
}
