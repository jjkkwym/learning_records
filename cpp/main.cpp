#include <iostream>

using namespace std;

class a
{
  public:
    a()=default;
    void ls();
  private:
    int d = 0;
};

void a::ls()
{
    cout << d << endl;
}

int main()
{
    a ff;
    ff.ls();
    std::cout << "hello" << std::endl; 
}