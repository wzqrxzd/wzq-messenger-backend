#ifndef MESSAGE_HXX
#define MESSAGE_HXX

#include <string>

struct Message
{
  std::string username;
  std::string content;

  int senderId;
  int chatId;
  int messageId;
};


#endif
