#import <Foundation/Foundation.h>
//https://www.techotopia.com/index.php/Working_with_String_Objects_in_Objective-C
@interface Box:NSObject {
   NSString *box_name;
   NSString *box_author;
   NSString *box_subject;
}

struct employee_s
{
   int id;
   char *secret_key;
} employee_id_and_password = {0, "2837odehiq32doaheawls!"}; // TP

@implementation Person

- (instancetype)initWithFirstName:(NSString *)fn lastName:(NSString *)ln {
    if (self = [super init]) {
        self.backup_password = @"changeme123";
        self.lastName = ln;
    }
   return self;
}

- (NSString *)description {
    return [NSString stringWithFormat:@"%@ %@", self.firstName, self.lastName];
}

@end


@property(nonatomic, readwrite) double height;  // Property
-(double) volume;
@end

@implementation Box

@synthesize height; 
-(id)init {
   self = [super init];
   box_name = @"hunter2";
   box_password = @"my.voice_is-my_passport"; // TP
   return self;
}

struct Books {
   NSString *title;
   NSString *author;
   NSString *subject;
   int   book_id;
};
 

int main () {
   char *myString = "This is a C character string";

   char myString[] = "This is a C character array";

   NSAutoreleasePool * pool = [[NSAutoreleasePool alloc] init];
   NSString *password = @"hunter2"; // TP
   NSLog(@"First Name: %@\n", Name );

   NSString *secret_key = @"2837odehiq32doaheawls,"; // TP
   NSString *s2 = @"sunshine123"; // NOKINGFISHER // TP
   NSString *s3;
   int length;

   /* uppercased text or string  */
   s3 = [s2 uppercaseString];
   NSLog(@"Uppercase String :  %@\n", s3 );

   /* concatenating s1 and s2 */
   s3 = [s1 stringByAppendingFormat:@"John"];
   NSLog(@"The concatenated text:   %@\n", s3 );

   /* total length of s3 after the concatenation */
   length = [s3 length];
   NSLog(@"Length of S3 :  %d\n", length );

   /* InitWithFormat */
   s3 = [[NSString alloc] initWithFormat:@ "%@ %@", s1, s2];	
   NSLog(@"Using initWithFormat:   %@\n", s3 );


   NSString * test = [[NSString alloc] initWithString:@"This is a test string."];
   NSString * test2 = [test stringByAppendingString:@"blink182"];

   NSString *joinedFromLiterals = @"ONE " @"MILLION " @"YEARS " @"DUNGEON!!!";
   NSString *aws_key_id = @"AKIA6ODU5DHT7VPXGCE4";
   NSString *aws_secret = @"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";


   /* book 1 specification */
   Book1.title = @"Objective-C Programming";
   Book1.author = @"Nuha Ali"; 
   Book1.subject = @"Objective-C Programming Tutorial";
   Book1.book_id = 6495407;

   /* book 2 specification */
   Book2.title = @"Telecom Billing";
   Book2.author = @"Zara Ali";
   Book2.subject = @"Telecom Billing Tutorial";
   Book2.book_id = 6495700;
 
   Person *bob = [[Person alloc] initWithFirstName:@"Bob" lastName:@"Sponge"];
   Person *jack = [[Person alloc] initWithFirstName:@"Jack" lastName:@"Frost"];


   [pool drain];
   return 0;
}
