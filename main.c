#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

typedef uint8_t u8;
typedef int16_t s16;
typedef uint16_t u16;
#define SIXTY_FOUR_K 65536

enum ip_protocol_e {
 PROTOCOL_HOPOPT,
 PROTOCOL_ICMP,
 PROTOCOL_IGMP,
 PROTOCOL_GGP,
 PROTOCOL_IPINIP,
 PROTOCOL_ST,
 PROTOCOL_TCP,
 PROTOCOL_CBT,
 PROTOCOL_EGP,
 PROTOCOL_IGP,
 PROTOCOL_BBNRCCMON,
 PROTOCOL_NVPII,
 PROTOCOL_PUP,
 PROTOCOL_ARGUS,
 PROTOCOL_EMCON,
 PROTOCOL_XNET,
 PROTOCOL_CHAOS,
 PROTOCOL_UDP,
 PROTOCOL_MUX,
 PROTOCOL_DCNMEAS,
 PROTOCOL_HMP,
 PROTOCOL_PRM,
 PROTOCOL_XNSIDP,
 PROTOCOL_TRUNK1,
 PROTOCOL_TRUNK2,
 PROTOCOL_LEAF1,
 PROTOCOL_LEAF2,
 PROTOCOL_RDP,
 PROTOCOL_IRTP,
 PROTOCOL_ISOTP4,
 PROTOCOL_NETBLT,
 PROTOCOL_MFENSP,
 PROTOCOL_MERITINP,
 PROTOCOL_DCCP,
 PROTOCOL_THREEPC,
 PROTOCOL_IDPR,
 PROTOCOL_XTP,
 PROTOCOL_DDP,
 PROTOCOL_IDPRCMTP,
 PROTOCOL_TPPLUSPLUS,
 PROTOCOL_IL,
 PROTOCOL_IPV6,
 PROTOCOL_SDRP,
 PROTOCOL_IPV6Route,
 PROTOCOL_IPV6Frag,
 PROTOCOL_IDRP,
 PROTOCOL_RSVP,
 PROTOCOL_GRE,
 PROTOCOL_DSR,
 PROTOCOL_BNA,
 PROTOCOL_ESP,
 PROTOCOL_AH,
 PROTOCOL_INLSP,
 PROTOCOL_SWLPE,
 PROTOCOL_NARP,
 PROTOCOL_MOBILE,
 PROTOCOL_TLSP,
 PROTOCOL_SKIP,
 PROTOCOL_IPV6ICMP,
 PROTOCOL_IPV6NONXT,
 PROTOCOL_IPV6OPTS,
 PROTOCOL_ANYHOSTINTERNALPROTOCOL,
 PROTOCOL_CFTP,
 PROTOCOL_ANYLOOCALNETWORK,
 PROTOCOL_SATEXPAK,
 PROTOCOL_KRYPTOLAN,
 PROTOCOL_RVD,
 PROTOCOL_IPPC,
 PROTOCOL_ANYDISTRIBUTEDFILESYSTEM,
 PROTOCOL_SATMON,
 PROTOCOL_VISA,
 PROTOCOL_IPCU,
 PROTOCOL_CPNX,
 PROTOCOL_CPHB,
 PROTOCOL_WSN,
 PROTOCOL_PVP,
 PROTOCOL_BRSATMON,
 PROTOCOL_SUNND,
 PROTOCOL_WBMON,
 PROTOCOL_WBEXPAK,
 PROTOCOL_ISOIP,
 PROTOCOL_VMTP,
 PROTOCOL_SECUREVMTP,
 PROTOCOL_VINES,
 PROTOCOL_TTP,
 PROTOCOL_IPTM,
 PROTOCOL_NSFNETIGP,
 PROTOCOL_DGP,
 PROTOCOL_TCF,
 PROTOCOL_EIGRP,
 PROTOCOL_OSPF,
 PROTOCOL_SPRITERPC,
 PROTOCOL_LARP,
 PROTOCOL_MTP,
 PROTOCOL_AX25,
 PROTOCOL_OS,
 PROTOCOL_MICP,
 PROTOCOL_SCCSP,
 PROTOCOL_ETHERIP,
 PROTOCOL_ENCAP,
 PROTOCOL_ANYPRIVATEENCRYPTIONSCHEME,
 PROTOCOL_GMTP,
 PROTOCOL_IFMP,
 PROTOCOL_PNNI,
 PROTOCOL_PIM,
 PROTOCOL_ARIS,
 PROTOCOL_SCPS,
 PROTOCOL_QNX,
 PROTOCOL_AN,
 PROTOCOL_IPCOMP,
 PROTOCOL_SNP,
 PROTOCOL_COMPAQPEER,
 PROTOCOL_IPXINIP,
 PROTOCOL_VRRP,
 PROTOCOL_PGM,
 PROTOCOL_ANY0HOPPROTOCOL,
 PROTOCOL_L2TP,
 PROTOCOL_DDX,
 PROTOCOL_IATP,
 PROTOCOL_STP,
 PROTOCOL_SRP,
 PROTOCOL_UTI,
 PROTOCOL_SMP,
 PROTOCOL_SM,
 PROTOCOL_PTP,
 PROTOCOL_ISISOVERIPV4,
 PROTOCOL_FIRE,
 PROTOCOL_CRTP,
 PROTOCOL_CRUDP,
 PROTOCOL_SSCOPMCE,
 PROTOCOL_IPLT,
 PROTOCOL_SPS,
 PROTOCOL_PIPE,
 PROTOCOL_SCTP,
 PROTOCOL_FC,
 PROTOCOL_RSVPE2EIGNORE,
 PROTOCOL_MOBILITYHEADER,
 PROTOCOL_UDPLITE,
 PROTOCOL_MPLSINIP,
 PROTOCOL_MANET,
 PROTOCOL_HIP,
 PROTOCOL_SHIM6,
 PROTOCOL_WESP,
 PROTOCOL_ROHC,
 PROTOCOL_ETHERNET,
 PROTOCOL_AGGFRAG,
 PROTOCOL_NSH,
 PROTOCOL_HOMA,
 PROTOCOL_BITEMU,
 PROTOCOL_UNASSIGNED,
};

typedef struct {
  u8 IpBuffer[4];
} ipv4_t;

typedef uint32_t u32;
#define ArrayCount(x) sizeof(x)/sizeof((x)[0])

ipv4_t BufferOffsetToIpV4( u8 *BufferOffset )
{
  ipv4_t Result;
  Result.IpBuffer[0] = BufferOffset[0];
  Result.IpBuffer[1] = BufferOffset[1];
  Result.IpBuffer[2] = BufferOffset[2];
  Result.IpBuffer[3] = BufferOffset[3];
  return(Result);
}

void PrintIpv4( const char *Name, ipv4_t Address )
{
  printf( "%s: %d.%d.%d.%d\n", Name, Address.IpBuffer[0],  Address.IpBuffer[1], Address.IpBuffer[2], Address.IpBuffer[3]);
}

u16 BigtoLittleU16( u8 *BufferOffset )
{
  u16 Result = ( BufferOffset[0] << 8) | BufferOffset[1];
  return (Result);
}

u32 BigtoLittleU32( u8 *BufferOffset )
{
  u32 Result = ( BufferOffset[0] << 24) | ( BufferOffset[1] << 16) | ( BufferOffset[2] << 8) | BufferOffset[3];
  return (Result);
}


// TODO(m2sprite|2025-06-23 18:10:56): Calculate checksum

void ParseTcp( u8 *Buffer, u32 BufferSize )
{
  u32 DataOffset = 0;
  printf("---------------TCP_PARSE---------------\n");
  printf("Tcp Buffer Size %u\n", BufferSize);
  if( BufferSize <  20 )
  {
    printf("Not valid tcp header we need at least 20 bytes\n");
    exit(21);
  }
  else
  {
    u32 AckNo = 0;
    u16 SrcPort = BigtoLittleU16( &Buffer[0] );
    u16 DstPort = BigtoLittleU16( &Buffer[2]);
    u32 SeqNo = BigtoLittleU32( &Buffer[4] );
    u8 Flags = Buffer[13];
    u8 CWR = (Flags & 0x80);
    u8 ECE = (Flags & 0x40);
    u8 URG = (Flags & 0x20);
    u8 ACK = (Flags & 0x10);
    u8 PSH = (Flags & 0x08);
    u8 RST = (Flags & 0x04);
    u8 SYN = (Flags & 0x02);
    u8 FIN = (Flags & 0x01);
    if( ACK )
    {
      AckNo = BigtoLittleU32( &Buffer[8] );
    }
    if( URG )
    {
      u16 UrgentPointer = BigtoLittleU16(&Buffer[18]);
      printf("UrgentPointer: %u\n", UrgentPointer);
    }
    u8 DataOffsetInHeader = (Buffer[12] & 0xF0) >> 4;
    u16 WindowLen = BigtoLittleU16(&Buffer[14]);
    u16 Checksum = BigtoLittleU16(&Buffer[16]);
    printf("SrcPort: %d \n", SrcPort);
    printf("DstPort: %d \n", DstPort);
    printf("SeqNo: %u\n", SeqNo);
    printf("AckNo: %u\n", AckNo);
    printf("DataOffset: %u\n", DataOffset);
    printf("WindowLen: %u\n", WindowLen);
    printf("Checksum: %u\n", Checksum);
    DataOffset = DataOffsetInHeader*4;
    if ( DataOffsetInHeader > 5)
    {
      printf(" Use DataOffset To parse options and then get data \n");
    }
  }
}

void ParseUdp( u8 *Buffer, u32 BufferSize )
{
  printf("---------------UDP_PARSE---------------\n");
  printf("Udp Buffer Size %u\n", BufferSize);
  if( BufferSize < 8 )
  {
    printf("Not a valid udp header we need at least 8 bytes\n");
    exit(21);
  }
  else
  {
    u16 SrcPort = BigtoLittleU16( &Buffer[0] );
    u16 DstPort = BigtoLittleU16( &Buffer[2]);
    u16 Length = BigtoLittleU16( &Buffer[4] );
    u16 Checksum = BigtoLittleU16( &Buffer[6] );
    printf("SrcPort: %d \n", SrcPort);
    printf("DstPort: %d \n", DstPort);
    printf("Length: %u\n", Length);
    printf("Checksum: %u\n", Checksum);
  }
}

void ParseIp( u8 *Buffer, u32 BufferSize )
{
  u32 DataOffset = 0;
  printf("---------------IP_PARSE---------------\n");
  printf("IP Buffer Size %zu\n", BufferSize);
  if( BufferSize <  20 )
  {
    printf("Not valid Ip header we need at least 20 bytes\n");
    exit(21);
  }
  else
  {
    u8 Version = (Buffer[0] & 0xF0) >> 4;
    u8 IHL = (Buffer[0] & 0x0F);
    u8 DSCP = (Buffer[1] & 0xFC) >> 2;
    u8 ECN = (Buffer[1] & 0x02);
    u16 TotalLength = BigtoLittleU16( &Buffer[2] );
    u16 Identification = BigtoLittleU16( &Buffer[4] );
    u8 Flags = (Buffer[6] & 0xE0) >> 5;
    u16 FragmentOffset = ((Buffer[6] & 0x1F) << 8 ) | Buffer[7];
    u8 TimeToLive = Buffer[8];
    u8 Protocol = Buffer[9];
    u16 HeaderChecksum = BigtoLittleU16(&Buffer[10]);
    ipv4_t SrcIP = BufferOffsetToIpV4(&Buffer[12]);
    ipv4_t DstIP = BufferOffsetToIpV4(&Buffer[16]);
    printf( "Version %d\n", Version );
    printf( "IHL %d\n", IHL );
    printf( "DSCP %d\n", DSCP );
    printf( "ECN %d\n", ECN );
    printf( "TotalLength %d\n", TotalLength );
    printf( "Identification %d\n", Identification );
    printf( "Flags %d\n", Flags );
    printf( "FragmentOffset %d\n", FragmentOffset );
    printf( "TimeToLive %d\n", TimeToLive );
    printf( "Protocol %d\n", Protocol );
    printf( "HeaderChecksum %d\n", HeaderChecksum );
    PrintIpv4("SrcIp", SrcIP);
    PrintIpv4("DstIp", DstIP);
    DataOffset = IHL*4;

    if ( IHL > 5)
    {
      printf(" Use IHL To parse options and then get data \n");
    }


    if( Protocol == PROTOCOL_TCP )
    {
      ParseTcp( &Buffer[DataOffset],  BufferSize - DataOffset );
    }
    else if( Protocol == PROTOCOL_UDP )
    {
      ParseUdp( &Buffer[DataOffset],  BufferSize - DataOffset );
    }

  }
}

int main(void)
{
  u8 IpPacketWithTCP[] = { 0x45, 0x00, 0x00, 0x3C, 0x1A, 0x2B, 0x40, 0x00, 0x40, 0x06, 0xB1, 0xE6, 0xC0, 0xA8, 0x01, 0x01, 0xC0, 0xA8, 0x01, 0x02,  0x00, 0x50, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x10, 0x20, 0x00, 0x1c, 0x46, 0x00, 0x00};
  u8 IpPacketWithUDP[] = { 0x45, 0x00, 0x00, 0x3C, 0x1A, 0x2B, 0x40, 0x00, 0x40, PROTOCOL_UDP, 0xB1, 0xE6, 0xC0, 0xA8, 0x01, 0x01, 0xC0, 0xA8, 0x01, 0x02, 0x1F, 0x90, 0x1F, 0x91, 0x00, 0x10,  0x00, 0x00};
  ParseIp( IpPacketWithTCP, ArrayCount( IpPacketWithTCP) );
  ParseIp( IpPacketWithUDP, ArrayCount( IpPacketWithUDP) );
}
