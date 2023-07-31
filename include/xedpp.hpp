#pragma once
extern "C"
{
	#include <xed/xed-interface.h>
	#include <xed/xed-operand-accessors.h>
};
#include <xstd/intrinsics.hpp>
#include <xstd/small_vector.hpp>
#include <xstd/assert.hpp>
#include <xstd/result.hpp>
#include <xstd/bitwise.hpp>
#include <xstd/enum_name.hpp>
#include <xstd/numeric_range.hpp>
#include <stdint.h>
#include <string>
#include <vector>
#include <ranges>
#include <unordered_set>
#include <initializer_list>

#pragma warning(disable: 4244)
#pragma warning(disable: 4267)

// Map all XED enums to use XED enum printer.
//
namespace xstd
{
	#define MAP_XED_ENUM( etype )                               \
	template<>                                                  \
	struct enum_name<xed_##etype##_t>                           \
	{                                                           \
		static std::string_view try_resolve( xed_##etype##_t n ) \
		{																		   \
			if ( n <= xed_##etype##_t_last() )						   \
				return xed_##etype##_t2str( n );                   \
			else																   \
				return {};													   \
		}																		   \
	    static std::string resolve( xed_##etype##_t n )         \
	    {                                                       \
	        if ( n <= xed_##etype##_t_last() )                  \
	            return xed_##etype##_t2str( n );                \
	        else                                                \
	            return std::to_string( n );                     \
	    }                                                       \
	};														 
	MAP_XED_ENUM( reg_enum                     );
	MAP_XED_ENUM( reg_class_enum               );
	MAP_XED_ENUM( error_enum                   );
	MAP_XED_ENUM( category_enum                );
	MAP_XED_ENUM( iclass_enum                  );
	MAP_XED_ENUM( iform_enum                   );
	MAP_XED_ENUM( exception_enum               );
	MAP_XED_ENUM( operand_enum                 );
	MAP_XED_ENUM( operand_type_enum            );
	MAP_XED_ENUM( operand_element_xtype_enum   );
	MAP_XED_ENUM( operand_width_enum           );
	MAP_XED_ENUM( operand_action_enum          );
	MAP_XED_ENUM( operand_visibility_enum      );
	MAP_XED_ENUM( nonterminal_enum             );
	MAP_XED_ENUM( operand_element_type_enum    );
	MAP_XED_ENUM( chip_enum                    );
	MAP_XED_ENUM( extension_enum               );
	MAP_XED_ENUM( attribute_enum               );
	MAP_XED_ENUM( isa_set_enum                 );
	MAP_XED_ENUM( machine_mode_enum            );
	MAP_XED_ENUM( address_width_enum           );
	MAP_XED_ENUM( flag_enum                    );
	MAP_XED_ENUM( flag_action_enum             );
#undef MAP_XED_ENUM
};

extern "C" {
	extern const xed_attributes_t xed_attributes[ 1 ];
	extern const xed_iform_info_t xed_iform_db[ 1 ];
};

// Declare a simple c++ wrapper around Intel XED.
//
namespace xed
{
	// Initialize XED tables before entry point.
	//
#if __has_attribute(constructor)
	[[gnu::constructor]] inline void __xed_init() { xed_tables_init(); }
#else
	extern "C" const inline int __xed_init = [ ] () { xed_tables_init(); return 0; }();
	#pragma comment(linker, "/include:__xed_init")
#endif

	// Renames.
	//
	using reg_t =             xed_reg_enum_t;
	using reg_class_t =       xed_reg_class_enum_t;
	using error_t =           xed_error_enum_t;
	using attribute_set_t =   xed_attributes_t;
	
	using category_t =        xed_category_enum_t;
	using iclass_t =          xed_iclass_enum_t;
	using iform_t =           xed_iform_enum_t;
	using exception_t =       xed_exception_enum_t;

	using op_name_t =         xed_operand_enum_t;
	using op_type_t =         xed_operand_type_enum_t;
	using op_xtype_t =        xed_operand_element_xtype_enum_t;
	using op_width_t =        xed_operand_width_enum_t;
	using op_action_t =       xed_operand_action_enum_t;
	using op_visibility_t =   xed_operand_visibility_enum_t;
	using op_nonterminal_t =  xed_nonterminal_enum_t;
	using op_element_type_t = xed_operand_element_type_enum_t;

	using chip_t =            xed_chip_enum_t;
	using extension_t =       xed_extension_enum_t;
	using attribute_t =       xed_attribute_enum_t;
	using isa_set_t =         xed_isa_set_enum_t;
	using mach_mode_t =       xed_machine_mode_enum_t;
	using adr_width_t =       xed_address_width_enum_t;

	using flag_t =            xed_flag_enum_t;
	using flag_info_t =       xed_simple_flag_t;
	using flag_action_t =     xed_flag_action_enum_t;
	
	using op_enc_type_t =     xed_encoder_operand_type_t;

	// Constants.
	//
	static constexpr size_t max_ins_len = 15;

	// Register properties.
	//
	inline constexpr bool is_ip( reg_t r ) { return r == XED_REG_RIP || r == XED_REG_EIP || r == XED_REG_IP; }
	inline constexpr bool is_sp( reg_t r ) { return r == XED_REG_RSP || r == XED_REG_ESP || r == XED_REG_SP; }
	inline constexpr bool is_flags( reg_t r ) { return r == XED_REG_RFLAGS || r == XED_REG_EFLAGS || r == XED_REG_FLAGS; }
	inline constexpr bool is_xmm( reg_t r ) { return XED_REG_XMM_FIRST <= r && r <= XED_REG_XMM_LAST; }
	inline constexpr bool is_ymm( reg_t r ) { return XED_REG_YMM_FIRST <= r && r <= XED_REG_YMM_LAST; }
	inline constexpr bool is_zmm( reg_t r ) { return XED_REG_ZMM_FIRST <= r && r <= XED_REG_ZMM_LAST; }
	inline constexpr bool is_vector( reg_t r ) { return is_xmm( r ) || is_ymm( r ) || is_zmm( r ); }
	inline constexpr bool is_mmx( reg_t r ) { return XED_REG_MMX0 <= r && r <= XED_REG_MMX7; }
	inline constexpr bool is_fpu( reg_t r ) { return XED_REG_X87_FIRST <= r && r <= XED_REG_X87_LAST; }
	inline constexpr bool is_segment_selector( reg_t r ) { return XED_REG_SR_FIRST <= r && r <= XED_REG_SR_LAST; }
	inline constexpr bool is_control_register( reg_t r ) { return XED_REG_CR_FIRST <= r && r <= XED_REG_CR_LAST; }
	inline constexpr bool is_kmask( reg_t r ) { return XED_REG_MASK_FIRST <= r && r <= XED_REG_MASK_LAST; }
	inline constexpr bool is_gpr64( reg_t r ) { return XED_REG_GPR64_FIRST <= r && r <= XED_REG_GPR64_LAST; }
	inline constexpr bool is_gpr32( reg_t r ) { return XED_REG_GPR32_FIRST <= r && r <= XED_REG_GPR32_LAST; }
	inline constexpr bool is_gpr16( reg_t r ) { return XED_REG_GPR16_FIRST <= r && r <= XED_REG_GPR16_LAST; }
	inline constexpr bool is_gpr8h( reg_t r ) { return XED_REG_GPR8h_FIRST <= r && r <= XED_REG_GPR8h_LAST; }
	inline constexpr bool is_gpr8( reg_t r ) { return XED_REG_GPR8_FIRST <= r && r <= XED_REG_GPR8_LAST; }
	inline constexpr bool is_gpr( reg_t r ) { return is_gpr64( r ) || is_gpr32( r ) || is_gpr16( r ) || is_gpr8( r ); }
	inline bitcnt_t register_bit_width( reg_t r, bool is_long = true )
	{
		if ( is_long )
			return xed_get_register_width_bits64( r );
		else
			return xed_get_register_width_bits( r );
	}
	inline size_t register_width( reg_t r, bool is_long = true )
	{
		return register_bit_width( r, is_long ) / 8;
	}
	inline reg_t extend_register( reg_t r, bool is_long = true )
	{
		return is_long ? xed_get_largest_enclosing_register( r ) : xed_get_largest_enclosing_register32( r );
	}
	inline reg_class_t register_class( reg_t r )
	{
		return xed_reg_class( r );
	}

	// Register mapping.
	//
	inline reg_t remap_register( reg_t r, size_t offset, size_t size )
	{
		auto parent = extend_register( r );

		// GPRs:
		//
		if ( is_gpr64( parent ) )
		{
			if ( size == 8 && offset == 0 )
				return parent;
			else if ( size == 4 && offset == 0 )
				return reg_t( ( r - XED_REG_GPR64_FIRST ) + XED_REG_GPR32_FIRST );
			else if ( size == 2 && offset == 0 )
				return reg_t( ( r - XED_REG_GPR64_FIRST ) + XED_REG_GPR16_FIRST );
			else if ( size == 1 && offset == 0 )
				return reg_t( ( r - XED_REG_GPR64_FIRST ) + XED_REG_GPR8_FIRST );
			else if ( size == 1 && offset == 1 && XED_REG_RAX <= parent && parent <= XED_REG_RBX )
				return reg_t( ( r - XED_REG_GPR64_FIRST ) + XED_REG_GPR8h_FIRST );
		}

		// Self:
		//
		if ( register_width( parent ) == size && offset == 0 )
			return parent;
		
		// Vector Registers:
		//
		if ( is_zmm( parent ) )
		{
			if ( size == ( 128 / 8 ) && offset == 0 )
				return reg_t( ( r - XED_REG_ZMM_FIRST ) + XED_REG_XMM_FIRST );
			else if ( size == ( 256 / 8 ) && offset == 0 )
				return reg_t( ( r - XED_REG_ZMM_FIRST ) + XED_REG_YMM_FIRST );
		}
		// -- If compiled witout AVX512:
		//
		else if ( is_ymm( parent ) )
		{
			if ( size == ( 128 / 8 ) && offset == 0 )
				return reg_t( ( r - XED_REG_YMM_FIRST ) + XED_REG_XMM_FIRST );
		}

		// RIP/RFLAGS:
		//
		if ( parent == XED_REG_RIP )
		{
			if ( size == 4 )
				return XED_REG_EIP;
			else if ( size == 2 )
				return XED_REG_IP;
			else
				return XED_REG_INVALID;
		}
		else if ( parent == XED_REG_RFLAGS )
		{
			if ( size == 4 )
				return XED_REG_EFLAGS;
			else if ( size == 2 )
				return XED_REG_FLAGS;
			else
				return XED_REG_INVALID;
		}
		return XED_REG_INVALID;
	}


	// Structure describing how a register maps to another register.
	//
	template<typename T = reg_t>
	struct register_mapping
	{
		// Base register of full size, e.g. X86_REG_RAX.
		//
		T base_register = {};

		// Offset of the current register from the base register.
		//
		uint8_t offset = 0;

		// Size of the current register in bytes.
		//
		uint8_t size = 0;

		auto tie() { return std::tie( base_register, offset, size ); }
	};
	inline register_mapping<> resolve_mapping( reg_t reg )
	{
		auto parent = extend_register( reg );
		if ( is_gpr8h( reg ) )
			return { parent, 1, ( uint8_t ) register_width( reg ) };
		else
			return { parent, 0, ( uint8_t ) register_width( reg ) };
	}

	// Status type.
	//
	struct status_traits
	{
		inline static constexpr error_t success_value = XED_ERROR_NONE;
		inline static constexpr error_t failure_value = XED_ERROR_LAST;
		template<typename T> inline static bool is_success( T st ) { return error_t( st ) == XED_ERROR_NONE; }
	};
	struct status
	{
		using status_traits = status_traits;

		error_t value;

		constexpr status( error_t v = XED_ERROR_GENERAL_ERROR ) noexcept : value( v ) {}
		constexpr status( const status& ) noexcept = default;
		constexpr status& operator=( const status& ) noexcept = default;

		explicit constexpr operator error_t() const { return value; }
		explicit constexpr operator bool() const { return value == XED_ERROR_NONE; }
		constexpr bool operator==( error_t other ) const { return value == other; }
		constexpr bool operator!=( error_t other ) const { return value != other; }
		constexpr bool operator==( status other ) const { return value == other.value; }
		constexpr bool operator!=( status other ) const { return value != other.value; }
		std::string to_string() const { return xstd::fmt::str( XSTD_ESTR( "XED error: %d" ), ( uint32_t ) value ); }
	};

	// Result type.
	//
	template<typename T = std::monostate>
	using result = xstd::basic_result<T, status>;

	// Machine modes.
	//
	using mode_t = xed_state_t;
	inline constexpr mode_t long64 =   { XED_MACHINE_MODE_LONG_64,        XED_ADDRESS_WIDTH_64b };
	inline constexpr mode_t long32 =   { XED_MACHINE_MODE_LONG_64,        XED_ADDRESS_WIDTH_32b };
	inline constexpr mode_t compat32 = { XED_MACHINE_MODE_LONG_COMPAT_32, XED_ADDRESS_WIDTH_32b };
	inline constexpr mode_t compat16 = { XED_MACHINE_MODE_LONG_COMPAT_16, XED_ADDRESS_WIDTH_16b };
	inline constexpr mode_t legacy32 = { XED_MACHINE_MODE_LEGACY_32,      XED_ADDRESS_WIDTH_32b };
	inline constexpr mode_t legacy16 = { XED_MACHINE_MODE_LEGACY_16,      XED_ADDRESS_WIDTH_16b };
	inline constexpr mode_t real32 =   { XED_MACHINE_MODE_REAL_32,        XED_ADDRESS_WIDTH_32b };
	inline constexpr mode_t real16 =   { XED_MACHINE_MODE_REAL_16,        XED_ADDRESS_WIDTH_16b };

	// Enum attributes.
	//
	static constexpr iclass_t jcc_list[] = {
		XED_ICLASS_JB,    XED_ICLASS_JNB,
		XED_ICLASS_JL,    XED_ICLASS_JNL,
		XED_ICLASS_JLE,   XED_ICLASS_JNLE,
		XED_ICLASS_JO,    XED_ICLASS_JNO,
		XED_ICLASS_JBE,   XED_ICLASS_JNBE,
		XED_ICLASS_JS,    XED_ICLASS_JNS,
		XED_ICLASS_JZ,    XED_ICLASS_JNZ,
		XED_ICLASS_JP,    XED_ICLASS_JNP,
		XED_ICLASS_JRCXZ, XED_ICLASS_JECXZ
	};
	static constexpr iclass_t ret_list[] = {
		XED_ICLASS_RET_NEAR, XED_ICLASS_RET_FAR,
	};
	static constexpr iclass_t sret_list[] = {
		XED_ICLASS_IRET, XED_ICLASS_IRETD, XED_ICLASS_IRETQ,
		XED_ICLASS_SYSRET, XED_ICLASS_SYSRET64, XED_ICLASS_SYSRET_AMD
	};
	
	inline iclass_t iform_to_iclass( iform_t iform )
	{
		if ( iform < XED_IFORM_LAST )
			return ( iclass_t ) xed_iform_db[ iform ].iclass;
		return XED_ICLASS_INVALID;
	}
	inline category_t iform_to_category( iform_t iform )
	{
		if ( iform < XED_IFORM_LAST )
			return ( category_t ) xed_iform_db[ iform ].category;
		return XED_CATEGORY_INVALID;
	}
	inline extension_t iform_to_extension( iform_t iform )
	{
		if ( iform < XED_IFORM_LAST )
			return ( extension_t ) xed_iform_db[ iform ].extension;
		return XED_EXTENSION_INVALID;
	}
	inline isa_set_t iform_to_isa_set( iform_t iform )
	{
		if ( iform < XED_IFORM_LAST )
			return ( isa_set_t ) xed_iform_db[ iform ].isa_set;
		return XED_ISA_SET_INVALID;
	}

	inline constexpr bool is_jcc( iclass_t iclass )
	{
		return std::find( std::begin( jcc_list ), std::end( jcc_list ), iclass ) != std::end( jcc_list );
	}
	inline constexpr iclass_t reverse_jcc( iclass_t iclass )
	{
		constexpr auto lim = std::end( jcc_list ) - 2;
		if ( auto it = std::find( std::begin( jcc_list ), lim, iclass ); it != lim )
		{
			size_t idx = ( it - &jcc_list[ 0 ] );
			return jcc_list[ idx ^ 1 ];
		}
		return XED_ICLASS_INVALID;
	}
	inline constexpr bool is_sret( iclass_t iclass )
	{
		return std::find( std::begin( ret_list ), std::end( ret_list ), iclass ) != std::end( ret_list );
	}
	inline constexpr bool is_uret( iclass_t iclass )
	{
		return iclass == XED_ICLASS_RET_NEAR || iclass == XED_ICLASS_RET_FAR;
	}
	inline constexpr bool is_ret( iclass_t iclass )
	{
		return is_uret( iclass ) || is_sret( iclass );
	}
	inline constexpr bool is_call( iclass_t iclass )
	{
		return iclass == XED_ICLASS_CALL_NEAR || iclass == XED_ICLASS_CALL_FAR;
	}
	inline constexpr bool is_jmp( iclass_t iclass )
	{
		return iclass == XED_ICLASS_JMP || iclass == XED_ICLASS_JMP_FAR;
	}
	inline bool is_register( op_name_t n )
	{
		return xed_operand_is_register( n );
	}
	inline bool is_adr_register( op_name_t n )
	{
		return xed_operand_is_memory_addressing_register( n );
	}
	inline constexpr bool is_read( op_action_t a, bool always = false )
	{
		switch ( a )
		{
			case XED_OPERAND_ACTION_R:   return true;
			case XED_OPERAND_ACTION_RW:  return true;
			case XED_OPERAND_ACTION_CR:  return !always;
			case XED_OPERAND_ACTION_RCW: return true;
			case XED_OPERAND_ACTION_CRW: return !always;
			default:                     return false;
		}
	}
	inline constexpr bool is_write( op_action_t a, bool always = false )
	{
		switch ( a )
		{
			case XED_OPERAND_ACTION_W:   return true;
			case XED_OPERAND_ACTION_RW:  return true;
			case XED_OPERAND_ACTION_CW:  return !always;
			case XED_OPERAND_ACTION_RCW: return !always;
			case XED_OPERAND_ACTION_CRW: return true;
			default:                     return false;
		}
	}
	inline constexpr bool is_overwrite( op_action_t a, bool always = false )
	{
		switch ( a )
		{
			case XED_OPERAND_ACTION_W:   return true;
			case XED_OPERAND_ACTION_CW:  return !always;
			default:                     return false;
		}
	}
	inline bool is_isa_set_valid_for_chip( isa_set_t isa, chip_t chip )
	{
		return xed_isa_set_is_valid_for_chip( isa, chip );
	}

	// Nopper.
	//
	static constexpr size_t max_nop_length = 9;
	static constexpr uint8_t nop_table[ max_nop_length + 1 ][ max_nop_length ] = {
		{},
		{ 0x90 },
		{ 0x66, 0x90 },
		{ 0x0F, 0x1F, 0x00 },
		{ 0x0F, 0x1F, 0x40, 0x00 },
		{ 0x0F, 0x1F, 0x44, 0x00, 0x00 },
		{ 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00 },
		{ 0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00 },
		{ 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 },
		{ 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 },
	};
	inline void nop( void* out, size_t length )
	{
		uint8_t* ptr = ( uint8_t* ) out;
		for ( ; length > max_nop_length; length -= max_nop_length, ptr += max_nop_length ) {
			memcpy( ptr, &nop_table[ max_nop_length ], max_nop_length );
		}
		memcpy( ptr, &nop_table[ length ], length );
	}
	inline void nop( void* from, void* to )
	{
		nop( from, ( uintptr_t ) to - ( uintptr_t ) from );

	}

	// Wrapped operand.
	//
	struct operand : xed_operand_t
	{
		// Properties.
		//
		reg_t reg() const { return xed_operand_reg( this ); }
		op_name_t name() const { return xed_operand_name( this ); }
		op_action_t action() const { return xed_operand_rw( this ); }
		op_nonterminal_t nonterminal_name() const { return xed_operand_nonterminal_name( this ); }
		op_visibility_t visibility() const { return xed_operand_operand_visibility( this ); }
		op_type_t type() const { return xed_operand_type( this ); }
		op_xtype_t xtype() const { return xed_operand_xtype( this ); }
		op_width_t width() const { return xed_operand_width( this ); }
		bool read( bool always = false ) const { return xed::is_read( action(), always ); }
		bool written( bool always = false ) const { return xed::is_write( action(), always ); }
		bool overwritten( bool always = false ) const { return xed::is_overwrite( action(), always ); }
		bool is_register() const { return xed::is_register( name() ); }
		bool is_address_register() const { return xed::is_adr_register( name() ); }
		bool template_is_register() const { return xed_operand_template_is_register( this ); }
		bool is_explicit() const { return visibility() == XED_OPVIS_EXPLICIT; }
		bool is_implicit() const { return visibility() == XED_OPVIS_IMPLICIT; }
		bool is_suppressed() const { return visibility() == XED_OPVIS_SUPPRESSED; }
		size_t width( size_t eff_op ) const { return bitcnt_t( width_bits( eff_op ) / 8 ); }
		bitcnt_t width_bits( size_t eff_op ) const
		{
			switch ( eff_op )
			{
				case 2:  return xed_operand_width_bits( this, 1 );
				case 4:  return xed_operand_width_bits( this, 2 );
				case 8:  return xed_operand_width_bits( this, 3 );
				default: return 0;
			}
		}
		
		// String conversion.
		//
		std::string to_string() const
		{
			std::string dump;
			dump.resize( 128 + 1 );
			xed_operand_print( this, dump.data(), dump.size() - 1 );
			dump.resize( strlen( dump.data() ) );
			return dump;
		}
	};
	
	// Wrapper for encoder operand types.
	//
	using encoder_operand = xed_encoder_operand_t;

	template<op_enc_type_t enc_type = XED_ENCODER_OPERAND_TYPE_OTHER>
	struct encoder_operand_t : encoder_operand
	{
		static constexpr op_enc_type_t type_id = enc_type;

		// Constructed by value or if type other, name and a value.
		//
		constexpr encoder_operand_t() { xed_encoder_operand_t::type = type_id; xed_encoder_operand_t::width_bits = 0; }
		constexpr encoder_operand_t( xed_encoder_operand_t op ) : xed_encoder_operand_t( op ) {}
		constexpr encoder_operand_t( op_name_t name, int32_t value ) : encoder_operand_t{}
		{
			xed_encoder_operand_t::u.s.operand_name = name;
			xed_encoder_operand_t::u.s.value = value;
		}

		// Getters and setters for width.
		//
		constexpr bitcnt_t width_bits() const { return xed_encoder_operand_t::width_bits; }
		constexpr void set_width_bits( bitcnt_t n ) { xed_encoder_operand_t::width_bits = n; }
		constexpr size_t width() const { return width_bits() / 8; }
		constexpr void set_width( size_t n ) { set_width_bits( bitcnt_t( n * 8 ) ); }

		// Casting.
		//
		static constexpr encoder_operand_t* cast( xed_encoder_operand_t* op ) { return op->type == type_id ? ( encoder_operand_t* ) op : nullptr; }
		static constexpr const encoder_operand_t* cast( const xed_encoder_operand_t* op ) { return cast( xstd::make_mutable( op ) ); }
	};
	struct reg : encoder_operand_t<XED_ENCODER_OPERAND_TYPE_REG>
	{
		inline constexpr reg( reg_t reg = XED_REG_INVALID )
		{
			u.reg = reg;
			set_width_bits( 0 );
		}

		// Getter.
		//
		inline constexpr reg_t value() const { return u.reg; }
		explicit operator reg_t() const { return value(); }

		// String conversion.
		//
		std::string to_string() const
		{
			return xstd::name_enum( value() );
		}
	};
	struct imm0u : encoder_operand_t<XED_ENCODER_OPERAND_TYPE_IMM0>
	{
		template<typename T = uint64_t> requires xstd::Castable<T, int64_t>
		inline constexpr imm0u( T value, const std::initializer_list<bitcnt_t>& sizes = { 8, 32, 64 } )
		{
			u.imm0 = ( uint64_t ) value;
			for ( auto& x : sizes )
			{
				if ( xstd::zero_extend( u.imm0, x ) == u.imm0 )
				{
					set_width_bits( x );
					return;
				}
			}
		}
		template<typename T = uint64_t> requires xstd::Castable<T, uint64_t>
		inline constexpr imm0u( T value, bitcnt_t n ) { u.imm0 = ( uint64_t ) value; set_width_bits( n ); }
		
		template<typename T> requires ( !xstd::Castable<T, uint64_t> && xstd::Castable<T, int64_t> )
		inline constexpr imm0u( T value, bitcnt_t n ) : imm0u( ( uint64_t ) ( int64_t ) value, n ) {}
		template<typename T> requires ( !xstd::Castable<T, uint64_t> && xstd::Castable<T, int64_t> )
		inline constexpr imm0u( T value, const std::initializer_list<bitcnt_t>& sizes = { 8, 32, 64 } ) : imm0u( ( uint64_t ) ( int64_t ) value, sizes ) {}

		// Getter.
		//
		inline constexpr uint64_t value() const { return u.imm0; }
		operator uint64_t() const { return value(); }

		// String conversion.
		//
		std::string to_string() const
		{
			return xstd::fmt::offset( value() );
		}
	};
	struct imm0 : encoder_operand_t<XED_ENCODER_OPERAND_TYPE_SIMM0>
	{
		template<typename T = int64_t> requires xstd::Castable<T, int64_t>
		inline constexpr imm0( T value, const std::initializer_list<bitcnt_t>& sizes = { 8, 32, 64 } )
		{
			u.imm0 = ( uint64_t ) ( int64_t ) value;
			for ( auto& x : sizes )
			{
				if ( xstd::sign_extend( u.imm0, x ) == u.imm0 )
				{
					if ( x == 64 ) type = XED_ENCODER_OPERAND_TYPE_IMM0; // Big hack.
					set_width_bits( x );
					return;
				}
			}
		}
		template<typename T = int64_t> requires xstd::Castable<T, int64_t>
		inline constexpr imm0( T value, bitcnt_t n ) { u.imm0 = ( uint64_t ) ( int64_t ) value; set_width_bits( n ); }
		
		template<typename T> requires ( !xstd::Castable<T, int64_t> && xstd::Castable<T, uint64_t> )
		inline constexpr imm0( T value, bitcnt_t n ) : imm0( ( int64_t ) ( uint64_t ) value, n ) {}
		template<typename T> requires ( !xstd::Castable<T, int64_t> && xstd::Castable<T, uint64_t> )
		inline constexpr imm0( T value, const std::initializer_list<bitcnt_t>& sizes = { 8, 32, 64 } ) : imm0( ( int64_t ) ( uint64_t ) value, sizes ) {}

		// Getter.
		//
		inline constexpr int64_t value() const { return ( int64_t ) u.imm0; }
		operator int64_t() const { return value(); }

		// String conversion.
		//
		std::string to_string() const
		{
			return xstd::fmt::offset( value() );
		}
	};
	struct imm1 : encoder_operand_t<XED_ENCODER_OPERAND_TYPE_IMM1>
	{
		inline constexpr imm1( uint8_t v )
		{
			u.imm1 = v;
			set_width_bits( 8 );
		}

		// Getter.
		//
		inline constexpr uint8_t value() const { return u.imm1; }
		operator uint8_t() const { return value(); }

		// String conversion.
		//
		std::string to_string() const
		{
			return xstd::fmt::str( "%02x", value() );
		}
	};
	struct relbr : encoder_operand_t<XED_ENCODER_OPERAND_TYPE_BRDISP>
	{
		inline constexpr relbr( int32_t v, bitcnt_t n = -1 )
		{
			u.brdisp = v;
			if ( n == -1 )
			{
				if ( xstd::sign_extend( v, 8 ) == v )
					n = 8;
				else
					n = 32;
			}
			set_width_bits( n );
		}

		// Getter.
		//
		inline constexpr int32_t value() const { return u.brdisp; }
		operator int32_t() const { return value(); }

		// String conversion.
		//
		std::string to_string() const
		{
			return xstd::fmt::offset( value() );
		}
	};
	struct ptr : encoder_operand_t<XED_ENCODER_OPERAND_TYPE_PTR>
	{
		inline constexpr ptr( int32_t v, bitcnt_t n = 0 )
		{
			u.brdisp = v;
			set_width_bits( !n ? ( xstd::sign_extend( v, 8 ) == v ? 8 : 32 ) : n );
		}

		// Getter.
		//
		inline constexpr int32_t value() const { return u.brdisp; }
		operator int32_t() const { return value(); }

		// String conversion.
		//
		std::string to_string() const
		{
			return xstd::fmt::offset( value() );
		}
	};
	struct seg0 : encoder_operand_t<XED_ENCODER_OPERAND_TYPE_SEG0>
	{
		inline constexpr seg0( reg_t reg ) 
		{
			u.reg = reg;
		}

		// Getter.
		//
		inline constexpr reg_t value() const { return u.reg; }
		explicit operator reg_t() const { return value(); }

		// String conversion.
		//
		std::string to_string() const
		{
			return xstd::name_enum( value() );
		}
	};
	struct seg1 : encoder_operand_t<XED_ENCODER_OPERAND_TYPE_SEG1>
	{
		inline constexpr seg1( reg_t reg )
		{
			u.reg = reg;
		}

		// Getter.
		//
		inline constexpr reg_t value() const { return u.reg; }
		explicit operator reg_t() const { return value(); }

		// String conversion.
		//
		std::string to_string() const
		{
			return xstd::name_enum( value() );
		}
	};
	// -- Pseudo-types for memory encoding.
	struct disp : xed_enc_displacement_t
	{
		inline constexpr disp( xed_enc_displacement_t d = { 0, 0 } ) : xed_enc_displacement_t{ d } {}
		inline constexpr disp( int64_t v, bitcnt_t n = -1 ) : xed_enc_displacement_t{ v, ( uint32_t ) n }
		{
			if ( n == -1 )
			{
				for ( auto& x : { 8, 32, 64 } )
				{
					if ( xstd::sign_extend( v, x ) == v )
					{
						xed_enc_displacement_t::displacement_bits = x;
						return;
					}
				}
			}
		}
		template<typename C, typename M>
		inline constexpr disp( xstd::member_reference_t<C, M> m, bitcnt_t n = -1 ) : disp( xstd::make_offset( m ), n ) {}

		// Disallow use of reg_t for safety.
		//
		disp( reg_t ) = delete;

		// Getter.
		//
		inline constexpr int64_t value() const { return displacement_bits ? displacement : 0; }
		explicit operator int64_t() const { return value(); }

		constexpr bitcnt_t width_bits() const { return displacement_bits; }
		constexpr void set_width_bits( bitcnt_t n ) { displacement_bits = n; }
		constexpr size_t width() const { return width_bits() / 8; }
		constexpr void set_width( size_t n ) { set_width_bits( bitcnt_t( n * 8 ) ); }

		// String conversion.
		//
		std::string to_string() const
		{
			return xstd::fmt::offset( value() );
		}
	};
	struct mseg
	{
		reg_t reg;
		inline constexpr mseg( reg_t r ) : reg( r ) {}
		inline constexpr mseg( seg0 r ) : reg( r.value() ) {}
		inline constexpr mseg( seg1 r ) : reg( r.value() ) {}
		inline constexpr mseg( xed::reg r ) : reg( r.value() ) {}

		// Getter.
		//
		inline constexpr reg_t value() const { return reg; }
		explicit operator reg_t() const { return value(); }

		// String conversion.
		//
		std::string to_string() const
		{
			return xstd::fmt::offset( value() );
		}
	};
	struct seg_es : mseg { constexpr seg_es() : mseg{ XED_REG_ES } {} };
	struct seg_ds : mseg { constexpr seg_ds() : mseg{ XED_REG_DS } {} };
	struct seg_cs : mseg { constexpr seg_cs() : mseg{ XED_REG_CS } {} };
	struct seg_ss : mseg { constexpr seg_ss() : mseg{ XED_REG_SS } {} };
	struct seg_fs : mseg { constexpr seg_fs() : mseg{ XED_REG_FS } {} };
	struct seg_gs : mseg { constexpr seg_gs() : mseg{ XED_REG_GS } {} };
	struct mem : encoder_operand_t<XED_ENCODER_OPERAND_TYPE_MEM>
	{
		explicit inline constexpr mem() : mem( 0, xed::disp{} ) {}

		// seg:[disp32]
		inline constexpr mem( bitcnt_t width_bits, disp d )
			: mem{ width_bits, XED_REG_INVALID, XED_REG_INVALID, XED_REG_INVALID, 0, d } { u.mem.disp.displacement_bits = 32; }
		inline constexpr mem( bitcnt_t width_bits, mseg seg, disp d = {} )
			: mem{ width_bits, seg, XED_REG_INVALID, XED_REG_INVALID, 0, d } { u.mem.disp.displacement_bits = 32; }

		// seg:[base + disp]
		inline constexpr mem( bitcnt_t width_bits, reg_t base, disp d = {} )
			: mem{ width_bits, XED_REG_INVALID, base, XED_REG_INVALID, 0, d } {}
		inline constexpr mem( bitcnt_t width_bits, mseg seg, reg_t base, disp d = {} )
			: mem{ width_bits, seg, base, XED_REG_INVALID, 0, d } {}
		
		// seg:[base + index * n + disp]
		inline constexpr mem( bitcnt_t width_bits, reg_t base, reg_t index, size_t scale, disp d = {} )
			: mem{ width_bits, XED_REG_INVALID, base, index, scale, d } {}
		inline constexpr mem( bitcnt_t width_bits, mseg seg, reg_t base, reg_t index, size_t scale, disp d = {} )
		{
			u.mem.seg = seg.reg;
			u.mem.base = base;
			u.mem.index = index;
			u.mem.scale = scale;
			u.mem.disp = d;
			set_width_bits( width_bits );
		}

		// Getters.
		//
		inline constexpr xed::disp disp() const { return u.mem.disp; }
		inline constexpr reg_t seg() const { return u.mem.seg; }
		inline constexpr reg_t base() const { return u.mem.base; }
		inline constexpr reg_t index() const { return u.mem.index; }
		inline constexpr size_t scale() const { return u.mem.scale; }
		
		// Setters.
		//
		inline constexpr void set_disp( xed::disp d ) { u.mem.disp = d; }
		inline constexpr void set_seg( reg_t r ) { u.mem.seg = r; }
		inline constexpr void set_base( reg_t r ) { u.mem.base = r; }
		inline constexpr void set_index( reg_t r ) { u.mem.index = r; }
		inline constexpr void set_scale( size_t n ) { u.mem.scale = n; }

		// String conversion.
		//
		std::string to_string() const
		{
			std::string segp;
			if ( seg() != XED_REG_INVALID )
				segp = xstd::name_enum( seg() ) + ":";
			
			if ( width_bits() == 512 )      segp = "ZMMWORD PTR " + segp;
			else if ( width_bits() == 256 ) segp = "YMMWORD PTR " + segp;
			else if ( width_bits() == 128 ) segp = "XMMWORD PTR " + segp;
			else if ( width_bits() == 80 )  segp = "TBYTE PTR " + segp;
			else if ( width_bits() == 64 )  segp = "QWORD PTR " + segp;
			else if ( width_bits() == 48 )  segp = "FWORD PTR " + segp;
			else if ( width_bits() == 32 )  segp = "DWORD PTR " + segp;
			else if ( width_bits() == 16 )  segp = "WORD PTR " + segp;
			else if ( width_bits() == 8 )   segp = "BYTE PTR " + segp;

			return xstd::fmt::str("%s[%s + %s * %u %s]",
				segp,
				base() != XED_REG_INVALID ? xstd::name_enum( base() ) : "0",
				index() != XED_REG_INVALID ? xstd::name_enum( index() ) : "0",
				scale(),
				xstd::fmt::offset( disp().value() )
			);
		}
	};

	// Wrapper around memory type with fixed width.
	//
	template<bitcnt_t N>
	struct simple_ptr : mem
	{
		inline constexpr simple_ptr( xed::disp d = {} ) : mem( N, d ) {}
		inline constexpr simple_ptr( mem m ) : mem( std::move( m ) ) { set_width_bits( N ); }
		inline constexpr simple_ptr( mseg seg, mem m ) : mem( std::move( m ) ) { set_seg( seg.reg ); set_width_bits( N ); }
		inline constexpr simple_ptr( reg_t base, xed::disp d = {} ) : mem( N, base, d ) {}
		inline constexpr simple_ptr( reg_t base, reg_t index, size_t scale, xed::disp d = {} ) : mem( N, base, index, scale, d ) {}
		inline constexpr simple_ptr( mseg seg, xed::disp d = {} ) : mem( N, seg, d ) {}
		inline constexpr simple_ptr( mseg seg, reg_t base, xed::disp d = {} ) : mem( N, seg, base, d ) {}
		inline constexpr simple_ptr( mseg seg, reg_t base, reg_t index, size_t scale, xed::disp d = {} ) : mem( N, seg, base, index, scale, d ) {}
	};
	using byte_ptr =    simple_ptr<8>;
	using word_ptr =    simple_ptr<16>;
	using dword_ptr =   simple_ptr<32>;
	using fword_ptr =   simple_ptr<48>;
	using qword_ptr =   simple_ptr<64>;
	using tbyte_ptr =   simple_ptr<80>;
	using xmmword_ptr = simple_ptr<128>;
	using ymmword_ptr = simple_ptr<256>;
	using zmmword_ptr = simple_ptr<512>;

	// Wrapped instruction.
	//
	struct instruction : xed_inst_t
	{
		// Properties.
		//
		uint8_t cpl() const { return this->_cpl; }
		iform_t iform() const { return ( iform_t ) this->_iform_enum; }
		iclass_t iclass() const { return iform_to_iclass( iform() ); }
		category_t category() const { return iform_to_category( iform() ); }
		extension_t extension() const { return iform_to_extension( iform() ); }
		isa_set_t isa_set() const { return iform_to_isa_set( iform() ); }
		uint32_t flag_info_index() const { return this->_flag_info_index; }
		const attribute_set_t& attribute_set() const { return xed_attributes[ this->_attributes ]; }
		bool attribute( attribute_t k ) const {
			auto& as = attribute_set();
			auto asi = ( k & 64 ) ? as.a2 : as.a1;
			return asi & ( 1ull << ( k & 63 ) );
		}
		exception_t exception() const { return ( exception_t ) this->_exceptions; }

		// Operands.
		//
		size_t num_operands() const { return this->_noperands; }
		const xed::operand* operand( size_t n ) const { return ( const xed::operand* ) xed_inst_operand( this, n ); }
		inline auto operands() const {
			return
				std::views::iota( 0ull, num_operands() ) |
				std::views::transform( [ this ] ( size_t n ) { return operand( n ); } );
		}
	};


	// Wrapped operand values.
	//
	struct dec_tag_t {};
	struct enc_tag_t {};
	struct operand_values : xed_operand_values_t
	{
		// Tag-dispatching based typed initializations.
		//
		inline operand_values() 
		{
			constexpr size_t N = sizeof( xed_operand_values_t );
			static_assert( !( N & 7 ), "Invalid size." );
			for ( size_t n = 0; n != (N/8); n++ )
				( ( uint64_t* ) this )[ n ] = 0;
		}
		inline operand_values( dec_tag_t ) : operand_values() {}
		inline operand_values( enc_tag_t ) : operand_values() {}
		inline operand_values( xed_decoded_inst_t ins, enc_tag_t ) : xed_operand_values_t( ins ) { xed_encoder_request_init_from_decode( this ); }

		// Default copy/move.
		//
		inline operand_values( operand_values&& ) noexcept = default;
		inline operand_values( const operand_values& ) = default;
		inline operand_values& operator=( operand_values&& ) noexcept = default;
		inline operand_values& operator=( const operand_values& ) = default;

		// String conversion.
		//
		std::string dump() const
		{
			std::string dump;
			dump.resize( 1024 + 1 );
			xed_operand_values_dump( this, dump.data(), dump.size() - 1 );
			dump.resize( strlen( dump.data() ) );
			return dump;
		}
		std::string to_string() const
		{
			std::string dump;
			dump.resize( 128 + 1 );
			xed_operand_values_print_short( this, dump.data(), dump.size() - 1 );
			dump.resize( strlen( dump.data() ) );
			return dump;
		}

		// Encoding details.
		//
		bool has_real_rep() const { return inst()->attribute( XED_ATTRIBUTE_REP ) && ( has_rep() || has_repne() ); }
		bool has_rep() const { return xed3_operand_get_rep( this ) == 3; }
		bool has_repne() const { return xed3_operand_get_rep( this ) == 2; }
		bool has_lock() const { return xed3_operand_get_lock( this ) != 0; }
		bool has_adrsz_prefix() const { return xed3_operand_get_asz( this ) != 0; }
		bool has_real_opsz_prefix() const { return xed3_operand_get_osz( this ) != 0; }
		bool has_opsz_prefix() const { return xed3_operand_get_prefix66( this ) != 0; }
		bool has_rexw_prefix() const { return xed3_operand_get_rexw( this ) != 0; }
		bool has_vex_prefix() const { return xed3_operand_get_vex_prefix( this ) != 0; }
		bool has_seg_prefix() const { return xed3_operand_get_seg_ovd( this ) != 0; }
		bool has_modrm() const { return xed3_operand_get_has_modrm( this ); }
		bool has_sib() const { return xed3_operand_get_has_sib( this ); }
		bool has_br_not_taken_hint() const { return xed3_operand_get_hint( this ) == 3; }
		bool has_br_taken_hint() const { return xed3_operand_get_hint( this ) == 4; }
		bool is_atomic_rmw() const { return xed_operand_values_get_atomic( this ); }
		bool is_mem_using_default_seg( size_t idx ) const { return xed_operand_values_using_default_segment( this, idx ); }
		bool is_mem_using_modrm() const { return !xed_operand_values_memop_without_modrm( this ); }
		reg_t seg_prefix() const { return xed_operand_values_segment_prefix( this ); }

		// Instruction properties.
		//
		const instruction* inst() const { return ( instruction* ) _inst; }
		bool is_valid() const { return inst() != nullptr; }
		bool is_valid( chip_t c ) const { return is_valid() && is_isa_set_valid_for_chip( isa_set(), c ); }
		bool is_prefetch() const { return xed_operand_values_is_prefetch( this ); }
		bool is_nop() const { return xed_operand_values_is_nop( this ); }
		bool is_mem() const { return xed_operand_values_accesses_memory( this ); }
		bool is_mpx() const { return xed_decoded_inst_has_mpx_prefix( this ); }
		bool is_xacquire() const { return xed_decoded_inst_is_xacquire( this ); }
		bool is_xrelease() const { return xed_decoded_inst_is_xrelease( this ); }
		category_t category() const { return inst()->category(); }
		extension_t extension() const { return inst()->extension(); }
		uint8_t cpl() const { return inst()->cpl(); }
		exception_t exception() const { return inst()->exception(); }
		isa_set_t isa_set() const { return inst()->isa_set(); }
		iform_t iform() const { return inst()->iform(); }
		iclass_t iclass() const { return inst()->iclass(); }
		bool attribute( attribute_t k ) const { return inst()->attribute( k ); }
		const flag_info_t* flag_info() const { return xed_decoded_inst_get_rflags_info( this ); }
		bool uses_flags() const { return xed_decoded_inst_uses_rflags( this ); }
		void set_iclass( iclass_t v ) { xed_operand_values_set_iclass( this, v ); }

		// Mode properties.
		//
		bool is_long_mode() const { return xed3_operand_get_mode( this ) == 2; }
		bool is_real_mode() const { return xed3_operand_get_realmode( this ) != 0; }
		bitcnt_t machine_mode_bits() const { return xed_decoded_inst_get_machine_mode_bits( this ); }
		void set_mode( const xed_state_t& state ) 
		{ 
			switch ( state.mmode )
			{
				case XED_MACHINE_MODE_LONG_64:
					xed3_operand_set_realmode( this, 0 );
					xed3_operand_set_mode( this, 2 );
					break;
				case XED_MACHINE_MODE_LEGACY_32:
				case XED_MACHINE_MODE_LONG_COMPAT_32:
					xed3_operand_set_realmode( this, 0 );
					xed3_operand_set_mode( this, 1 );
					break;
				case XED_MACHINE_MODE_REAL_16:
					xed3_operand_set_realmode( this, 1 );
					xed3_operand_set_mode( this, 0 );
					break;
				case XED_MACHINE_MODE_REAL_32:
					xed3_operand_set_realmode( this, 1 );
					xed3_operand_set_mode( this, 1 );
					break;
				case XED_MACHINE_MODE_LEGACY_16:
				case XED_MACHINE_MODE_LONG_COMPAT_16:
					xed3_operand_set_realmode( this, 0 );
					xed3_operand_set_mode( this, 0 );
					break;
			}
			switch ( state.stack_addr_width )
			{
				case XED_ADDRESS_WIDTH_16b:
					xed3_operand_set_smode( this, 0 );
					break;
				case XED_ADDRESS_WIDTH_32b:
					xed3_operand_set_smode( this, 1 );
					break;
				case XED_ADDRESS_WIDTH_64b:
					xed3_operand_set_smode( this, 2 );
					break;
				default:
					break;
			}
		}

		chip_t input_chip() const { return xed_decoded_inst_get_input_chip( this ); }
		void set_input_chip( chip_t c ) { xed_decoded_inst_set_input_chip( this, c ); }

		size_t eff_op_width() const { return eff_op_width_bits() / 8; }
		size_t eff_adr_width() const { return eff_adr_width_bits() / 8; }
		bitcnt_t eff_op_width_bits() const { return xed_operand_values_get_effective_operand_width( this ); }
		bitcnt_t eff_adr_width_bits() const { return xed_operand_values_get_effective_address_width( this ); }
		bitcnt_t stack_width_bits() const { return xed_operand_values_get_stack_address_width( this ); }

		void set_eff_op_width( bitcnt_t n ) { set_eff_op_width_bits( n * 8 ); }
		void set_eff_adr_width( bitcnt_t n ) { set_eff_adr_width_bits( n * 8 ); }
		void set_eff_op_width_bits( bitcnt_t n ) { xed_operand_values_set_effective_operand_width( this, n ); }
		void set_eff_adr_width_bits( bitcnt_t n ) { xed_operand_values_set_effective_address_width( this, n ); }

		// Encoding details.
		//
		uint8_t modrm() const { return xed_decoded_inst_get_modrm( this ); }
		size_t num_prefixes() const { return xed_decoded_inst_get_nprefixes( this ); }

		// SSE/AVX details.
		//
		bool is_broadcast() const { return xed_decoded_inst_is_broadcast( this ); }
		bool is_explicit_broadcast() const { return xed_decoded_inst_is_broadcast_instruction( this ); }
		bool is_embedded_broadcast() const { return xed_decoded_inst_uses_embedded_broadcast( this ); }
		bool is_masking() const { return xed_decoded_inst_masking( this ); }
		bool is_merging() const { return xed_decoded_inst_merging( this ); }
		bool is_zeroing() const { return xed_decoded_inst_zeroing( this ); }
		bool is_sse() const { return xed_classify_sse( this ); }
		bool is_avx() const { return xed_classify_avx( this ); }
		bool is_avx512() const { return xed_classify_avx512( this ); }
		bool is_avx512_maskop() const { return xed_classify_avx512_maskop( this ); }
		bool is_masked_vec() const { return xed_decoded_inst_masked_vector_operation( xstd::make_mutable( this ) ); }
		bitcnt_t vec_len() const { return xed_decoded_inst_vector_length_bits( this ); }
		size_t operand_elements( size_t n ) const { return xed_decoded_inst_operand_elements( this, n ); }
		bitcnt_t operand_element_width( size_t n ) const { return operand_element_width_bits( n ) / 8; }
		bitcnt_t operand_element_width_bits( bitcnt_t n ) const { return xed_decoded_inst_operand_element_size_bits( this, n ); }
		op_element_type_t operand_element_type( size_t n ) const { return xed_decoded_inst_operand_element_type( this, n ); }

		// Operand properties.
		//
		bool has_relbr() const { return relbr_width_bits() != 0; }
		bool has_disp() const { return xed_operand_values_has_displacement( this ); }
		bool has_imm() const { return imm_width_bits() != 0; }
		bool has_imm1() const { return xed3_operand_get_imm1( this ); }
		size_t num_operands() const { return inst()->num_operands(); }
		const xed::operand* operand( size_t n ) const { return inst()->operand( n ); }
		decltype( auto ) operands() const { return inst()->operands(); }
		op_action_t action( size_t n ) const { return xed_decoded_inst_operand_action( this, n ); }
		size_t operand_width() const { return xed_decoded_inst_get_operand_width( this ); }
		bitcnt_t operand_len( size_t n ) const { return operand_len_bits( n ) / 8; }
		bitcnt_t operand_len_bits( bitcnt_t n ) const { return xed_decoded_inst_operand_length_bits( this, n ); }
		bool has_mem_disp() const { return xed_operand_values_has_memory_displacement( this ); }
		bool is_relative() const
		{
			if ( has_relbr() )
				return true;
			for ( size_t n = 0; n != num_mem_operands(); n++ )
				if ( is_ip( mem_base( n ) ) )
					return true;
			return false;
		}

		// Immediate operands.
		//
		bool is_imm0_signed() const { return xed3_operand_get_imm0signed( this ); }
		int64_t imm0_value() const { return xed_operand_values_get_immediate_int64( this ); }
		uint64_t imm0u_value() const { return xed3_operand_get_uimm0( this ); }
		uint64_t imm1u_value() const { return xed3_operand_get_uimm1( this ); }
		uint8_t imm1_value() const { return xed3_operand_get_imm1( this ); }
		xed::imm0 imm0() const { return { imm0_value(), imm_width_bits() }; }
		xed::imm1 imm1() const { return { imm1_value() }; }
		xed::imm0u imm0u() const { return { imm0u_value(), imm_width_bits() }; }
		size_t imm_width() const { return xed3_operand_get_imm_width( this ) / 8; }
		bitcnt_t imm_width_bits() const { return xed3_operand_get_imm_width( this ); }
		void set_imm0( const xed::imm0& v ) { xed_operand_values_set_immediate_signed_bits( this, v.value(), v.width_bits() ); }
		void set_imm0u( const xed::imm0u& v ) { xed_operand_values_set_immediate_unsigned_bits( this, v.value(), v.width_bits() ); }
		void set_imm1( const xed::imm1& v ) { xed3_operand_set_imm1( this, v.value() ); }

		// Relative branch operand.
		//
		size_t relbr_width() const { return relbr_width_bits(); }
		bitcnt_t relbr_width_bits() const { return xed3_operand_get_brdisp_width( this ); }
		int32_t relbr_value() const { return relbr_width_bits() ? xed3_operand_get_disp( this ) : 0; }
		xed::relbr relbr() const { return { relbr_value(), relbr_width_bits() }; }
		void set_relbr( const xed::relbr& r ) { xed_operand_values_set_branch_displacement_bits( this, r.value(), r.width_bits() ); }

		// Register operands.
		//
		size_t num_reg_operands() const 
		{ 
			for ( size_t n = 0;; n++ ) 
				if ( reg( n ) == XED_REG_INVALID ) 
					return n; 
			unreachable(); 
		}
		reg_t reg( op_name_t name ) const { return xed_decoded_inst_get_reg( this, name ); }
		void set_reg( op_name_t name, reg_t reg ) { xed_operand_values_set_operand_reg( this, name, reg ); }
		reg_t reg( size_t idx ) const { return idx <= 8 ? ( reg_t ) ( ( &_operands.reg0 )[ idx ] ) : XED_REG_INVALID; }
		void set_reg( size_t idx, reg_t reg ) { fassert( idx <= 8 ); ( &_operands.reg0 )[ idx ] = reg; }

		// Memory operands.
		//
		size_t num_mem_operands() const { return xed_decoded_inst_number_of_memory_operands( this ); }
		size_t mem_width( size_t idx ) const { return xed_decoded_inst_get_memory_operand_length( this, idx ); }
		bitcnt_t mem_width_bits( size_t idx ) const { return mem_width( idx ) * 8; }
		reg_t mem_seg( size_t idx ) const { return xed_operand_values_get_seg_reg( this, idx ); }
		reg_t mem_base( size_t idx ) const { return xed_operand_values_get_base_reg( this, idx ); }
		reg_t mem_index( size_t idx ) const { return idx ? XED_REG_INVALID : xed_operand_values_get_index_reg( this, idx ); }
		xed::disp mem_disp( size_t idx ) const { return { mem_disp_value( idx ), mem_disp_width_bits( idx ) }; }
		int64_t mem_disp_value( size_t idx ) const { return idx ? 0 : xed_operand_values_get_memory_displacement_int64( this ); }
		size_t mem_disp_width( size_t idx ) const { return idx ? 0 : xed_operand_values_get_memory_displacement_length( this ); }
		bitcnt_t mem_disp_width_bits( size_t idx ) const { return idx ? 0 : xed_operand_values_get_memory_displacement_length_bits( this ); }
		size_t mem_scale( size_t idx ) const { return idx ? 0 : xed_operand_values_get_scale( this ); }
		xed::mem mem( size_t idx ) const { return { mem_width_bits( idx ), mem_seg( idx ), mem_base( idx ), mem_index( idx ), mem_scale( idx ), mem_disp( idx ) }; }

		void set_mem_width_bits( bitcnt_t n ) { set_mem_width( n / 8 ); }
		void set_mem_width( size_t n ) { xed_operand_values_set_memory_operand_length( this, n ); }
		void set_mem_seg( size_t idx, reg_t v ) { xed_operand_values_set_seg_reg( this, idx, v ); }
		void set_mem_base( size_t idx, reg_t v ) { xed_operand_values_set_base_reg( this, idx, v ); }
		void set_mem_index( size_t idx, reg_t v ) { fassert( idx == 0 ); xed_operand_values_set_index_reg( this, idx, v ); }
		void set_mem_disp( size_t idx, const xed::disp& d ) { fassert( idx == 0 ); xed_operand_values_set_memory_displacement_bits( this, d.value(), d.displacement_bits ); }
		void set_mem_scale( size_t idx, size_t scale ) { fassert( idx == 0 ); xed_operand_values_set_scale( this, idx, scale ); }
		void set_mem( size_t idx, const xed::mem& m )
		{
			if ( idx == 0 ) set_mem_width_bits( m.width_bits() );
			set_mem_seg( idx, m.seg() );
			set_mem_base( idx, m.base() );
			set_mem_index( idx, m.index() );
			set_mem_scale( idx, m.scale() );
			set_mem_disp( idx, m.disp() );
		}

		// User data.
		//
		void* user_data() const { return ( void* ) u.user_data; }
		void set_user_data( void* p ) { u.user_data = ( uint64_t ) p; }
	};

	// Wrapped decoded instruction.
	//
	struct decoding : operand_values
	{
		// Tag dispatching.
		//
		inline decoding( enc_tag_t ) : operand_values( enc_tag_t{} ) {}
		inline decoding( xed_decoded_inst_t src, enc_tag_t ) : operand_values( src, enc_tag_t{} ) {}

		// Default copy/move/init, explicit decay to base.
		//
		inline decoding() : operand_values( dec_tag_t{} ) {}
		inline decoding( decoding&& ) = default;
		inline decoding( const decoding& ) = default;
		inline decoding& operator=( decoding&& ) = default;
		inline decoding& operator=( const decoding& ) = default;
		operand_values& opval() { return *this; }
		const operand_values& opval() const { return *this; }

		// String conversion.
		//
		std::string dump() const
		{
			std::string dump;
			dump.resize( 1024 + 1 );
			xed_decoded_inst_dump( this, dump.data(), dump.size() - 1 );
			dump.resize( strlen( dump.data() ) );
			return dump;
		}
		bool to_string( char* buffer, size_t length, uint64_t address = 0 ) const
		{
			return xed_format_context( XED_SYNTAX_INTEL, this, buffer, length, address, nullptr, nullptr );
		}
		std::string to_string( uint64_t address = 0 ) const
		{
			std::string dump( 128 + 1, 0 );
			if ( to_string( dump.data(), dump.size() - 1 ) )
			{
				dump.resize( strlen( dump.data() ) );
				return dump;
			}
			return XSTD_ESTR( "Error" );
		}

		// Instruction properties.
		//
		size_t length() const { return this->_decoded_length; }
		uint8_t at( size_t n ) const { return xed_decoded_inst_get_byte( this, n ); }
		uint8_t operator[]( size_t n ) const { return at( n ); }

		// Memory operands.
		//
		size_t mem_adr_width( size_t idx ) const { return xed_decoded_inst_get_memop_address_width( this, idx ); }
		bitcnt_t mem_adr_width_bits( size_t idx ) const { return mem_adr_width( idx ) * 8; }

		// Patch API.
		//
		void patch_disp( uint8_t* at, xed::disp value ) const { xed_patch_disp( ( xed_decoded_inst_t* ) this, at, value ); }
		void patch_relbr( uint8_t* at, xed::relbr value ) const { xed_patch_relbr( ( xed_decoded_inst_t* ) this, at, value ); }
		void patch_imm0( uint8_t* at, xed::imm0 value ) const { xed_patch_imm0( ( xed_decoded_inst_t* ) this, at, value ); }
	};
	// Wrapped encoder request.
	//
	struct adjust_rip_t {};
	struct encoding : decoding
	{
		// Construction from decoding or a mode.
		//
		inline encoding( const mode_t& mode ) : decoding( enc_tag_t{} ) { set_mode( mode ); }
		inline encoding( const decoding& dec ) : decoding( dec, enc_tag_t{} ) {}
		
		// Default copy/move/init, explicit decay to base.
		//
		inline encoding() : decoding( enc_tag_t{} ) {}
		inline encoding( encoding&& ) = default;
		inline encoding( const encoding& ) = default;
		inline encoding& operator=( encoding&& ) = default;
		inline encoding& operator=( const encoding& ) = default;
		decoding& dec() { return *this; }
		const decoding& dec() const { return *this; }

		// String conversion.
		//
		std::string to_string( uint64_t address = 0 ) const
		{
			std::string dump;
			dump.resize( 1024 + 1 );
			xed_encode_request_print( this, dump.data(), dump.size() - 1 );
			dump.resize( strlen( dump.data() ) );
			return dump;
		}

		// Instruction details.
		//
		iclass_t iclass() const { return xed_encoder_request_get_iclass( this ); }
		void set_iclass( iclass_t cl ) { xed_encoder_request_set_iclass( this, cl ); }
		void set_eff_op_width( bitcnt_t n ) { set_eff_op_width_bits( n * 8 ); }
		void set_eff_adr_width( bitcnt_t n ) { set_eff_adr_width_bits( n * 8 ); }
		void set_eff_op_width_bits( bitcnt_t n ) { xed_encoder_request_set_effective_operand_width( this, n ); }
		void set_eff_adr_width_bits( bitcnt_t n ) { xed_encoder_request_set_effective_address_size( this, n ); }

		// Operand order.
		//
		size_t num_operand_orders() const { return xed_encoder_request_operand_order_entries( xstd::make_mutable( this ) ); }
		void reset_operand_order() { return xed_encoder_request_zero_operand_order( this ); }
		op_name_t operand_order( size_t idx ) const { return xed_encoder_request_get_operand_order( xstd::make_mutable( this ), idx ); }
		void set_operand_order( size_t idx, op_name_t name ) { xed_encoder_request_set_operand_order( this, idx, name ); }

		// Encoding API.
		//
		result<xstd::small_vector<uint8_t, max_ins_len>> encode()
		{
			// Allocate the result bytes.
			//
			result<xstd::small_vector<uint8_t, max_ins_len>> res = {};

			// First try with no changes, if it fails, try every possible combination.
			//
			uint32_t len = 0;
			auto&    out = res.result.emplace();
			res.status = xed_encode( this, out.space, max_ins_len, ( uint32_t* ) &len );
			if ( res.status != XED_ERROR_NONE ) {
				for ( int8_t n = 3; n >= 0; n-- ) {
					this->_operands.error = 0;
					this->_operands.eosz =  ( uint8_t ) n;
					auto status = xed_encode( this, out.space, max_ins_len, ( uint32_t* ) &len );
					if ( status == XED_ERROR_NONE ) {
						res.status = XED_ERROR_NONE;
						break;
					}
				}
			}
			out.length = len & 15;
			return res;
		}
		result<xstd::small_vector<uint8_t, max_ins_len>> encode() const {
			auto prev = eff_op_width_bits();
			auto result = const_cast< encoding* >( this )->encode();
			const_cast< encoding* >( this )->set_eff_op_width_bits( prev );
			return result;
		}
	};

	// Encoding from iclass + operands.
	//
	inline encoding vencode( const mode_t& mode, iclass_t icl, std::initializer_list<xed_encoder_operand_t> ops )
	{
		xed_encoder_instruction_t inst = {};
		xed_inst( &inst, mode, icl, 0, ops.size(), ops.begin() );
		encoding enc_req = { mode };
		xed_convert_to_encoder_request( &enc_req, &inst );
		return enc_req;
	}
	inline encoding vencode64( iclass_t icl, std::initializer_list<xed_encoder_operand_t> ops ) { return vencode( long64, icl, ops ); }
	inline encoding vencode32( iclass_t icl, std::initializer_list<xed_encoder_operand_t> ops ) { return vencode( compat32, icl, ops ); }
	template<typename... Tx> inline encoding encode( const mode_t& mode, iclass_t icl, Tx&&... ops ) { return vencode( mode, icl, { ops... } ); }
	template<typename... Tx> inline encoding encode64( iclass_t icl, Tx&&... ops ) { return encode( long64, icl, std::forward<Tx>( ops )... ); }
	template<typename... Tx> inline encoding encode32( iclass_t icl, Tx&&... ops ) { return encode( compat32, icl, std::forward<Tx>( ops )... ); }

	// Decoding.
	//
	inline static result<decoding> decode( const mode_t& mode, const void* data, size_t length )
	{
		result<decoding> ins = {};
		auto& out = ins.result.emplace();
		out.set_mode( mode );
		ins.status = xed_decode( &out, ( const uint8_t* ) data, length );
		return ins;
	}
	inline static std::vector<decoding> decode_n( const mode_t& mode, const void* data, size_t length )
	{
		std::vector<decoding> res;
		const uint8_t* iterator = ( const uint8_t* ) data;
		while ( auto ins = decode( mode, iterator, length ) )
		{
			iterator += ins->length();
			length -= ins->length();
			res.emplace_back( std::move( *ins ) );
			if ( !length ) break;
		}
		return res;
	}
	inline static result<decoding> decode64( const void* data, size_t length = max_ins_len ) { return decode( long64, data, length ); }
	inline static result<decoding> decode32( const void* data, size_t length = max_ins_len ) { return decode( compat32, data, length ); }
	inline static std::vector<decoding> decode32_n( const void* data, size_t length ) { return decode_n( compat32, data, length ); }
	inline static std::vector<decoding> decode64_n( const void* data, size_t length ) { return decode_n( long64, data, length ); }
	template <typename T = std::initializer_list<uint8_t>> requires xstd::ContiguousIterable<T>
	inline static result<decoding> decode64( const T& container ) { return decode( long64, &*std::begin( container ), std::size( container ) * sizeof( xstd::iterable_val_t<T> ) ); }
	template <typename T = std::initializer_list<uint8_t>> requires xstd::ContiguousIterable<T>
	inline static result<decoding> decode32( const T& container ) { return decode( compat32, &*std::begin( container ), std::size( container ) * sizeof( xstd::iterable_val_t<T> ) ); }
	template <typename T = std::initializer_list<uint8_t>> requires xstd::ContiguousIterable<T>
	inline static std::vector<decoding> decode64_n( const T& container ) { return decode_n( long64, &*std::begin( container ), std::size( container ) * sizeof( xstd::iterable_val_t<T> ) ); }
	template <typename T = std::initializer_list<uint8_t>> requires xstd::ContiguousIterable<T>
	inline static std::vector<decoding> decode32_n( const T& container ) { return decode_n( compat32, &*std::begin( container ), std::size( container ) * sizeof( xstd::iterable_val_t<T> ) ); }

	// Lenght-only decoding.
	//
	inline size_t decode_len( const mode_t& mode, const void* data, size_t length = max_ins_len ) 
	{
		xed::decoding dec = {};
		dec.set_mode( mode );
		if ( xed_ild_decode( &dec, ( const uint8_t* ) data, length ) == XED_ERROR_NONE )
			return dec.length();
		else
			return 0;
	}
	inline size_t decode_len64( const void* data, size_t length = max_ins_len ) { return decode_len( long64, data, length ); }
	inline size_t decode_len32( const void* data, size_t length = max_ins_len ) { return decode_len( compat32, data, length ); }
};

// Implement [Rm + I].
//
inline constexpr xed::mem operator+( xed::mem a, xed::disp d )
{
	a.set_disp( a.disp().value() + d.value() );
	return a;
}
inline constexpr xed::mem operator-( xed::mem a, xed::disp d )
{
	a.set_disp( a.disp().value() - d.value() );
	return a;
}
// -- Allow register instead of memory.
inline constexpr xed::mem operator+( const xed::reg& a, xed::disp d ) { return xed::mem{ 0, a.value() } + xed::disp( d ); };
inline constexpr xed::mem operator-( const xed::reg& a, xed::disp d ) { return xed::mem{ 0, a.value() } - xed::disp( d ); };
// -- Displacement replaced with integer types and also the inverse for addition.
inline constexpr xed::mem operator+( xed::mem a, int64_t d ) { return std::move( a ) + xed::disp( d ); };
inline constexpr xed::mem operator-( xed::mem a, int64_t d ) { return std::move( a ) - xed::disp( d ); };
inline constexpr xed::mem operator+( const xed::reg& a, int64_t d ) { return xed::mem{ 0, a.value() } + xed::disp( d ); };
inline constexpr xed::mem operator-( const xed::reg& a, int64_t d ) { return xed::mem{ 0, a.value() } - xed::disp( d ); };
inline constexpr xed::mem operator+( int64_t d, xed::mem a ) { return std::move( a ) + xed::disp( d ); };
inline constexpr xed::mem operator+( xed::disp d, xed::mem a ) { return std::move( a ) + xed::disp( d ); };
inline constexpr xed::mem operator+( int64_t d, const xed::reg& a ) { return xed::mem{ 0, a.value() } + xed::disp( d ); };
inline constexpr xed::mem operator+( xed::disp d, const xed::reg& a ) { return xed::mem{ 0, a.value() } + xed::disp( d ); };

// Implement [R*N].
//
inline constexpr xed::mem operator*( xed::mem a, size_t n )
{
	if ( a.base() == XED_REG_INVALID && a.index() != XED_REG_INVALID )
	{
		a.set_scale( a.scale() * n );
		return a;
	}
	else if ( a.index() == XED_REG_INVALID && a.base() != XED_REG_INVALID )
	{
		a.set_index( a.base() );
		a.set_base( XED_REG_INVALID );
		a.set_scale( n );
		return a;
	}
	else if ( auto d = a.disp().value() )
	{
		a.set_disp( d * n );
		return a;
	}
	fassert( false ); // Invalid
}
// -- Allow register instead of memory and also the inverse.
inline constexpr xed::mem operator*( const xed::reg& a, size_t d ) { return xed::mem{ 0, a.value() } * d; };
inline constexpr xed::mem operator*( size_t d, xed::mem a ) { return std::move( a ) * d; };
inline constexpr xed::mem operator*( size_t d, const xed::reg& a ) { return xed::mem{ 0, a.value() } * d; };

// Implement [R+Rm].
//
inline constexpr xed::mem operator+( xed::mem a, xed::mem b )
{
	// Fix segment bases.
	//
	for ( auto* m : { &a, &b } )
	{
		if ( m->base() == XED_REG_GSBASE )
		{
			m->set_base( XED_REG_INVALID );
			m->set_seg( XED_REG_GS );
		}
		else if ( m->index() == XED_REG_GSBASE && m->scale() == 1 )
		{
			m->set_index( XED_REG_INVALID );
			m->set_seg( XED_REG_GS );
		}
		else if ( m->base() == XED_REG_FSBASE )
		{
			m->set_base( XED_REG_INVALID );
			m->set_seg( XED_REG_FS );
		}
		else if ( m->index() == XED_REG_FSBASE && m->scale() == 1 )
		{
			m->set_index( XED_REG_INVALID );
			m->set_seg( XED_REG_FS );
		}
	}

	// Normalize into a.
	//
	if ( a.seg() == XED_REG_INVALID )
		a.set_seg( b.seg() );
	if ( !a.width_bits() )
		a.set_width_bits( b.width_bits() );

	// Accumulate all registers.
	//
	int32_t disp = 0;
	std::pair<xed::reg_t, size_t> regs[ 2 ] = { {} };
	size_t size = 0;
	auto push = [ & ] ( xed::reg_t r, size_t n = 1 ) -> bool
	{
		if ( n == 0 ) return true;
		if ( !size )
		{
			size = 1;
			regs[ 0 ] = { r, n };
			return true;
		}
		for ( auto& [k, v] : regs )
		{
			if ( k == r )
			{
				v += n;
				return true;
			}
		}
		if ( size == 2 )
			return false;
		size = 2;
		regs[ 1 ] = { r, n };
		return true;
	};
	for ( auto* m : { &a, &b } )
	{
		if ( m->base() != XED_REG_INVALID && !push( m->base() ) )
			fassert( false ); // Invalid
		if ( m->index() != XED_REG_INVALID && !push( m->index(), m->scale() ) )
			fassert( false ); // Invalid
		if ( int32_t d = m->disp().value() )
			disp += d;
	}

	// Emplace back into a.
	//
	switch ( size )
	{
		case 0:
		{
			a.set_disp( disp );
			return a;
		}
		case 1:
		{
			if ( regs[ 0 ].second != 1 )
			{
				a.set_base( XED_REG_INVALID );
				a.set_index( regs[ 0 ].first );
				a.set_scale( regs[ 0 ].second );
			}
			else
			{
				a.set_base( regs[ 0 ].first );
				a.set_index( XED_REG_INVALID );
				a.set_scale( 0 );
			}
			return a;
		}
		case 2:
		{
			if ( regs[ 0 ].second == 1 )
			{
				a.set_base( regs[ 0 ].first );
				a.set_index( regs[ 1 ].first );
				a.set_scale( regs[ 1 ].second );
				return a;
			}
			else if ( regs[ 1 ].second == 1 )
			{
				a.set_base( regs[ 1 ].first );
				a.set_index( regs[ 0 ].first );
				a.set_scale( regs[ 0 ].second );
				return a;
			}
			[[fallthrough]];
		}
		default:
			fassert( false ); // Invalid
	}
}
// -- Allow register instead of memory and also the inverse.
inline constexpr xed::mem operator+( const xed::reg& a, xed::mem b ) { return xed::mem{ 0, a.value() } + std::move( b ); };
inline constexpr xed::mem operator+( xed::mem b, const xed::reg& a ) { return xed::mem{ 0, a.value() } + std::move( b ); };
inline constexpr xed::mem operator+( const xed::reg& a, const xed::reg& b ) { return xed::mem{ 0, a.value() } + xed::mem{ 0, b.value() }; };