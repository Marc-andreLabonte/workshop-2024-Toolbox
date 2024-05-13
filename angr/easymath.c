#include<stdio.h>


void solve(int x) {

   int y = x * 8 + 3;

   if (y == 35) {
     printf("correct answer");
   } else {
     printf("Try again");
   }
}

int main() {

    solve(32);
    return 0;

}
