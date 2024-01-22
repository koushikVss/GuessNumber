#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define MIN_NUMBER 1
#define MAX_NUMBER 100

int main() {
    // Seed the random number generator with the current time
    srand(time(NULL));

    // Generate a random number between MIN_NUMBER and MAX_NUMBER
    int answer = MIN_NUMBER + rand() % MAX_NUMBER;

    int guess, attempts = 0;

    printf("Welcome to the Number Guessing Game!\n");
    printf("I have selected a number between %d and %d. Try to guess it.\n", MIN_NUMBER, MAX_NUMBER);

    do {
        printf("Enter your guess: ");
        scanf("%d", &guess);

        attempts++;

        if (guess == answer) {
            printf("Congratulations! You guessed the correct number in %d attempts.\n", attempts);
        } else if (guess < answer) {
            printf("Too low. Try again.\n");
        } else {
            printf("Too high. Try again.\n");
        }

    } while (guess != answer);

    return 0;
}
