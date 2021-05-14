#pragma once
extern "C"
{
	#include <xed/xed-interface.h>
};
#include <xstd/intrinsics.hpp>
#include <xstd/small_vector.hpp>
#include <xstd/assert.hpp>
#include <xstd/result.hpp>
#include <xstd/range.hpp>
#include <xstd/numeric_range.hpp>
#include <stdint.h>
#include <string>
#include <vector>
#include <unordered_set>
#include <initializer_list>

#pragma warning(disable: 4244)
#pragma warning(disable: 4267)

// Declare a simple c++ wrapper around Intel XED.
//
namespace xed
{
	// Initialize XED tables before entry point.
	//
#if __has_attribute(constructor)
	[[gnu::constructor]] inline void __xed_init() { xed_tables_init(); }
#else
	extern "C" const inline int __xed_init = [ ] () { return ( ( int( * )( ) )xed_tables_init )( ); }( );
	#pragma comment(linker, "/include:__xed_init")
#endif

	static constexpr size_t max_ins_len = 15;

	// Structure describing how a register maps to another register.
	//
	template<typename T>
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
	};

	// register =(*n)=> [base_register] @ unique{ offset, size }
	//
	struct register_map
	{
		static constexpr size_t max_entry_count = ( size_t ) XED_REG_LAST;
		static constexpr size_t max_xref_count = 8;
		static constexpr size_t invalid_xref = ~0ull;

		// Type of entries provided in the constructor.
		//
		using linear_entry_t = std::pair<xed_reg_enum_t, register_mapping<xed_reg_enum_t>>;
		struct lookup_entry_t : register_mapping<xed_reg_enum_t>
		{
			// Only for the parent, xref list will be assigned a list of children.
			//
			size_t xrefs[ max_xref_count ] = { 0 };
			constexpr lookup_entry_t()
			{
				for ( size_t& v : xrefs )
					v = invalid_xref;
			}
		};

		// Lookup table type, and conversion into it.
		//
		lookup_entry_t linear_entries[ max_entry_count ] = {};
		inline constexpr register_map( std::initializer_list<linear_entry_t> entries )
		{
			for ( auto&& [id, entry] : entries )
			{
				// Must be the only reference to it.
				//
				auto& entry_n = linear_entries[ ( size_t ) id ];
				dassert( entry_n.size == 0 );

				// Write base details.
				//
				entry_n.base_register = entry.base_register;
				entry_n.offset = entry.offset;
				entry_n.size = entry.size;

				// Add xref to base register.
				//
				bool xref_added = false;
				for ( auto& xref : linear_entries[ ( size_t ) entry.base_register ].xrefs )
				{
					if ( xref == invalid_xref )
					{
						xref = ( size_t ) id;
						xref_added = true;
						break;
					}
				}
				dassert( xref_added );
			}
		}

		// Gets the offset<0> and size<1> of the mapping for the given register.
		//
		inline constexpr register_mapping<xed_reg_enum_t> resolve_mapping( uint32_t _reg ) const
		{
			// xed_reg_enum_try to find the register mapping, if successful return.
			//
			auto& entry = linear_entries[ _reg ];
			if ( entry.size )
				return entry;

			// Otherwise return default mapping.
			//
			auto parent = extend( _reg );
			return { parent, 0, uint8_t( xed_get_register_width_bits64( parent ) / 8 ) };
		}

		// Gets the base register for the given register.
		//
		inline xed_reg_enum_t extend( uint32_t _reg ) const
		{
			return xed_get_largest_enclosing_register( xed_reg_enum_t( _reg ) );
		}

		// Remaps the given register at given specifications.
		//
		inline constexpr xed_reg_enum_t remap( uint32_t _reg, uint32_t offset, uint32_t size ) const
		{
			// xed_reg_enum_try to find the register mapping, if successful:
			//
			auto& entry = linear_entries[ _reg ];
			if ( entry.size )
			{
				// Get base register entry, enumerate xrefs.
				//
				auto& bentry = linear_entries[ _reg = ( uint32_t ) entry.base_register ];
				fassert( bentry.size != 0 );

				for ( size_t xref : bentry.xrefs )
				{
					if ( xref != invalid_xref )
					{
						auto& pentry = linear_entries[ ( size_t ) xref ];

						if ( pentry.base_register == entry.base_register &&
							 pentry.offset == offset &&
							 pentry.size == size )
						{
							return ( xed_reg_enum_t ) xref;
						}
					}
				}
			}

			// If we fail to find, and we're strictly remapping to a full register, return as is.
			//
			fassert( offset == 0 );
			return ( xed_reg_enum_t ) _reg;
		}

		// Checks whether the register is a generic register that is handled.
		//
		inline constexpr bool is_generic( uint32_t _reg ) const
		{
			return linear_entries[ _reg ].size != 0;
		}
	};

	// Table of GP regs.
	//
	static const std::unordered_set<xed_reg_enum_t> x86_32_gp_regs = {
		XED_REG_EAX, XED_REG_EBX, XED_REG_ECX, XED_REG_EDX,
		XED_REG_ESI, XED_REG_EDI, XED_REG_EBX, XED_REG_EBP,
	};
	static const std::unordered_set<xed_reg_enum_t> x86_64_gp_regs = {
		XED_REG_RAX, XED_REG_RBX, XED_REG_RCX, XED_REG_RDX,
		XED_REG_RSI, XED_REG_RDI, XED_REG_RBX, XED_REG_RBP,
		XED_REG_R8,  XED_REG_R9,  XED_REG_R10, XED_REG_R11, 
		XED_REG_R12, XED_REG_R13, XED_REG_R14, XED_REG_R15
	};

	// Xed register mapping.
	//
	inline constexpr register_map registers =
	{
		{
            /* [Instance]           [Base]       [Offset] [Size]  */
            { XED_REG_RAX,		{ XED_REG_RAX,		0,		8	} },
            { XED_REG_EAX,		{ XED_REG_RAX,		0,		4	} },
            { XED_REG_AX,		{ XED_REG_RAX,		0,		2	} },
            { XED_REG_AH,		{ XED_REG_RAX,		1,		1	} },
            { XED_REG_AL,		{ XED_REG_RAX,		0,		1	} },
                    
            { XED_REG_RBX,		{ XED_REG_RBX,		0,		8	} },
            { XED_REG_EBX,		{ XED_REG_RBX,		0,		4	} },
            { XED_REG_BX,		{ XED_REG_RBX,		0,		2	} },
            { XED_REG_BH,		{ XED_REG_RBX,		1,		1	} },
            { XED_REG_BL,		{ XED_REG_RBX,		0,		1	} },
                    
            { XED_REG_RCX,		{ XED_REG_RCX,		0,		8	} },
            { XED_REG_ECX,		{ XED_REG_RCX,		0,		4	} },
            { XED_REG_CX,		{ XED_REG_RCX,		0,		2	} },
            { XED_REG_CH,		{ XED_REG_RCX,		1,		1	} },
            { XED_REG_CL,		{ XED_REG_RCX,		0,		1	} },
                    
            { XED_REG_RDX,		{ XED_REG_RDX,		0,		8	} },
            { XED_REG_EDX,		{ XED_REG_RDX,		0,		4	} },
            { XED_REG_DX,		{ XED_REG_RDX,		0,		2	} },
            { XED_REG_DH,		{ XED_REG_RDX,		1,		1	} },
            { XED_REG_DL,		{ XED_REG_RDX,		0,		1	} },
                    
            { XED_REG_RDI,		{ XED_REG_RDI,		0,		8	} },
            { XED_REG_EDI,		{ XED_REG_RDI,		0,		4	} },
            { XED_REG_DI,		{ XED_REG_RDI,		0,		2	} },
            { XED_REG_DIL,		{ XED_REG_RDI,		0,		1	} },
                    
            { XED_REG_RSI,		{ XED_REG_RSI,		0,		8	} },
            { XED_REG_ESI,		{ XED_REG_RSI,		0,		4	} },
            { XED_REG_SI,		{ XED_REG_RSI,		0,		2	} },
            { XED_REG_SIL,		{ XED_REG_RSI,		0,		1	} },
                    
            { XED_REG_RBP,		{ XED_REG_RBP,		0,		8	} },
            { XED_REG_EBP,		{ XED_REG_RBP,		0,		4	} },
            { XED_REG_BP,		{ XED_REG_RBP,		0,		2	} },
            { XED_REG_BPL,		{ XED_REG_RBP,		0,		1	} },
                    
            { XED_REG_RSP,		{ XED_REG_RSP,		0,		8	} },
            { XED_REG_ESP,		{ XED_REG_RSP,		0,		4	} },
            { XED_REG_SP,		{ XED_REG_RSP,		0,		2	} },
            { XED_REG_SPL,		{ XED_REG_RSP,		0,		1	} },
                    
            { XED_REG_R8,		{ XED_REG_R8,		0,		8	} },
            { XED_REG_R8D,		{ XED_REG_R8,		0,		4	} },
            { XED_REG_R8W,		{ XED_REG_R8,		0,		2	} },
            { XED_REG_R8B,		{ XED_REG_R8,		0,		1	} },
                    
            { XED_REG_R9,		{ XED_REG_R9,		0,		8	} },
            { XED_REG_R9D,		{ XED_REG_R9,		0,		4	} },
            { XED_REG_R9W,		{ XED_REG_R9,		0,		2	} },
            { XED_REG_R9B,		{ XED_REG_R9,		0,		1	} },

            { XED_REG_R10,		{ XED_REG_R10,		0,		8	} },
            { XED_REG_R10D,		{ XED_REG_R10,		0,		4	} },
            { XED_REG_R10W,		{ XED_REG_R10,		0,		2	} },
            { XED_REG_R10B,		{ XED_REG_R10,		0,		1	} },

            { XED_REG_R11,		{ XED_REG_R11,		0,		8	} },
            { XED_REG_R11D,		{ XED_REG_R11,		0,		4	} },
            { XED_REG_R11W,		{ XED_REG_R11,		0,		2	} },
            { XED_REG_R11B,		{ XED_REG_R11,		0,		1	} },

            { XED_REG_R12,		{ XED_REG_R12,		0,		8	} },
            { XED_REG_R12D,		{ XED_REG_R12,		0,		4	} },
            { XED_REG_R12W,		{ XED_REG_R12,		0,		2	} },
            { XED_REG_R12B,		{ XED_REG_R12,		0,		1	} },

            { XED_REG_R13,		{ XED_REG_R13,		0,		8	} },
            { XED_REG_R13D,		{ XED_REG_R13,		0,		4	} },
            { XED_REG_R13W,		{ XED_REG_R13,		0,		2	} },
            { XED_REG_R13B,		{ XED_REG_R13,		0,		1	} },

            { XED_REG_R14,		{ XED_REG_R14,		0,		8	} },
            { XED_REG_R14D,		{ XED_REG_R14,		0,		4	} },
            { XED_REG_R14W,		{ XED_REG_R14,		0,		2	} },
            { XED_REG_R14B,		{ XED_REG_R14,		0,		1	} },

            { XED_REG_R15,		{ XED_REG_R15,		0,		8	} },
            { XED_REG_R15D,		{ XED_REG_R15,		0,		4	} },
            { XED_REG_R15W,		{ XED_REG_R15,		0,		2	} },
            { XED_REG_R15B,		{ XED_REG_R15,		0,		1	} },
		}
	};

	// Status type.
	//
	struct status
	{
		xed_error_enum_t value;

		constexpr status( xed_error_enum_t v = XED_ERROR_GENERAL_ERROR ) noexcept : value( v ) {}
		constexpr status( const status& ) noexcept = default;
		constexpr status& operator=( const status& ) noexcept = default;

		explicit constexpr operator xed_error_enum_t() const { return value; }
		explicit constexpr operator bool() const { return value == XED_ERROR_NONE; }
		constexpr bool operator==( xed_error_enum_t other ) const { return value == other; }
		constexpr bool operator!=( xed_error_enum_t other ) const { return value != other; }
		constexpr bool operator==( status other ) const { return value == other.value; }
		constexpr bool operator!=( status other ) const { return value != other.value; }
		std::string to_string() const { return xstd::fmt::str( XSTD_ESTR( "XED error: %d" ), ( uint32_t ) value ); }

		// Inline traits.
		//
		inline static constexpr xed_error_enum_t success_value = XED_ERROR_NONE;
		inline static constexpr xed_error_enum_t failure_value = XED_ERROR_LAST;
		inline static bool is_success( status st ) { return st.value == XED_ERROR_NONE; }
	};

	// Result type.
	//
	template<typename T = std::monostate>
	using result = xstd::result<T, status>;

	// Easier format for memory access details.
	//
	struct mem_details
	{
		// <length> seg:[base+idx*scale+{disp#disp_width}]:
		//
		xed_reg_enum_t seg, base, idx;
		uint32_t scale;
		int64_t disp;
		size_t disp_width;
		size_t length;

		// Access mode.
		//
		bool read;
		bool write;
	};

	// Wrapped decoded instruction.
	//
	struct decoded_instruction : xed_decoded_inst_t
	{
		// Default copy/move.
		//
		inline decoded_instruction() { xed_decoded_inst_zero( this ); }
		inline decoded_instruction( decoded_instruction&& ) = default;
		inline decoded_instruction( const decoded_instruction& ) = default;
		inline decoded_instruction& operator=( decoded_instruction&& ) = default;
		inline decoded_instruction& operator=( const decoded_instruction& ) = default;

		// Helpers.
		//
		inline std::string to_string( uint64_t address = 0 ) const
		{
			char buffer[ 64 ];
			if ( xed_format_context( XED_SYNTAX_INTEL, this, buffer, 64, address, nullptr, nullptr ) )
				return buffer;
			return "???";
		}
		inline size_t length() const { return xed_decoded_inst_get_length( this ); }
		inline xed_iclass_enum_t get_class() const { return xed_decoded_inst_get_iclass( this ); }
		inline const xed_simple_flag_t* get_flag_info() const { return xed_decoded_inst_get_rflags_info( this ); }
		inline bool is_valid() const { return xed_decoded_inst_valid( this ); }
		inline bool is_long() const { return xed_operand_values_get_long_mode( this ); }
		inline int32_t branch_disp() const { return xed_decoded_inst_get_branch_displacement( this ); }
		inline size_t branch_disp_width() const { return xed_decoded_inst_get_branch_displacement_width( this ); }
		inline size_t num_mem_operands() const { return xed_decoded_inst_number_of_memory_operands( this ); }
		inline xed_reg_enum_t mem_seg_reg( size_t idx ) const { return xed_decoded_inst_get_seg_reg( this, idx ); }
		inline xed_reg_enum_t mem_base_reg( size_t idx ) const { return xed_decoded_inst_get_base_reg( this, idx ); }
		inline xed_reg_enum_t mem_index_reg( size_t idx ) const { return xed_decoded_inst_get_index_reg( this, idx ); }
		inline uint32_t mem_scale( size_t idx ) const { return xed_decoded_inst_get_scale( this, idx ); }
		inline int64_t mem_disp( size_t idx ) const { return xed_decoded_inst_get_memory_displacement( this, idx ); }
		inline size_t mem_disp_width( size_t idx ) const { return xed_decoded_inst_get_memory_displacement_width( this, idx ); }
		inline size_t mem_length( size_t idx ) const { return xed_decoded_inst_get_memory_operand_length( this, idx ); }
		inline bool mem_read( size_t idx ) const { return xed_decoded_inst_mem_read( this, idx ); }
		inline bool mem_write( size_t idx ) const { return xed_decoded_inst_mem_written( this, idx ); }
		inline bool mem_overwrite( size_t idx ) const { return xed_decoded_inst_mem_written_only( this, idx ); }
		inline mem_details get_mem( size_t idx ) const
		{
			return {
				.seg = mem_seg_reg( idx ), .base = mem_base_reg( idx ), .idx = mem_index_reg( idx ),
				.scale = mem_scale( idx ), .disp = mem_disp( idx ), .disp_width = mem_disp_width( idx ),
				.length = mem_length( idx ), .read = mem_read( idx ), .write = mem_write( idx )
			};
		}
		inline size_t num_operands() const { return xed_decoded_inst_noperands( this ); }
		inline const xed_operand_t* get_operand( size_t n ) const { return xed_inst_operand( xed_decoded_inst_inst( this ), n ); }
		inline const xed_operand_t* get_visible_operand( size_t n ) const
		{
			for ( size_t i = 0;; i++ )
			{
				auto op = get_operand( i );
				if ( !op ) break;
				if ( xed_operand_operand_visibility( op ) != XED_OPVIS_SUPPRESSED && !n-- )
					return op;
			}
			return nullptr;
		}
		inline auto operands() const
		{
			return xstd::make_range(
				xstd::numeric_iterator<>{ 0ull }, xstd::numeric_iterator<>{ num_operands() },
				[ this ] ( size_t n ) { return get_operand( n ); }
			);
		}
		inline xstd::small_vector<const xed_operand_t*, 8> visible_operands() const
		{
			xstd::small_vector<const xed_operand_t*, 8> vec;
			for ( auto op : operands() )
			{
				if ( xed_operand_operand_visibility( op ) != XED_OPVIS_SUPPRESSED )
					vec.emplace_back( op );
			}
			return vec;
		}
		inline xed_reg_enum_t get_reg( xed_operand_enum_t op ) const { return xed_decoded_inst_get_reg( this, op ); }
		inline xed_reg_enum_t get_reg( const xed_operand_t* op ) const { return get_reg( xed_operand_name( op ) ); }
	};

	// Wrapped encoder request.
	//
	struct encoder_request : xed_encoder_request_t
	{
		// Default copy/move.
		//
		inline encoder_request() { xed_encoder_request_zero( this ); }
		encoder_request( encoder_request&& ) = default;
		encoder_request( const encoder_request& ) = default;
		encoder_request& operator=( encoder_request&& ) = default;
		encoder_request& operator=( const encoder_request& ) = default;

		// Conversion from and to decoded instruction.
		//
		inline encoder_request( const decoded_instruction& ins ) : xed_encoder_request_t( ins )
		{
			xed_encoder_request_init_from_decode( this );
		}
		inline operator decoded_instruction() const
		{
			auto bytes = encode();
			decoded_instruction ins = {};
			xed_operand_values_init_keep_mode( &ins, this );
			fassert( xed_decode( &ins, bytes->data(), bytes->size() ) == XED_ERROR_NONE );
			return ins;
		}

		// Helpers.
		//
		inline bool is_long() const { return xed_operand_values_get_long_mode( this ); }
		inline result<xstd::small_vector<uint8_t, max_ins_len>> encode() const
		{
			auto mut = const_cast< encoder_request* >( this );

			result<xstd::small_vector<uint8_t, max_ins_len>> res = {};
			auto& tmp = res.result.emplace();
			tmp.resize( max_ins_len );

			// Try every possible combination and if none works fail.
			//
			for ( auto n : { 0, 64, 32, 16, 8 } )
			{
				if ( n == 64 && !is_long() ) continue;
				if ( n ) xed_encoder_request_set_effective_operand_width( mut, n );
				
				uint32_t len = 0;
				auto status = xed_encode( mut, tmp.data(), max_ins_len, ( uint32_t* ) &len );
				if ( !n ) res.status = status;
				
				if ( status == XED_ERROR_NONE )
				{
					res.status = status;
					tmp.resize( len );
					break;
				}
			}
			return res;
		}
	};

	// Decoding and encoding API.
	//
	inline static result<decoded_instruction> decode( const void* data, bool is_long, size_t length )
	{
		result<decoded_instruction> ins = {};
		if ( is_long )
			xed_decoded_inst_set_mode( &ins.result.emplace(), XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b );
		else
			xed_decoded_inst_set_mode( &ins.result.emplace(), XED_MACHINE_MODE_LONG_COMPAT_32, XED_ADDRESS_WIDTH_32b );
		ins.status = xed_decode( &ins.result.value(), ( const uint8_t* ) data, length );
		return ins;
	}
	inline static std::vector<decoded_instruction> decode_n( const void* data, bool is_long, size_t length )
	{
		std::vector<decoded_instruction> res;
		const uint8_t* iterator = ( const uint8_t* ) data;
		while ( auto ins = decode( iterator, is_long, length ) )
		{
			iterator += ins->length();
			length -= ins->length();
			res.emplace_back( std::move( *ins ) );
			if ( !length ) break;
		}
		return res;
	}
	inline static result<encoder_request> encode( xed_iclass_enum_t opcode, bool is_long, const xed_encoder_operand_t* ops, size_t num_ops )
	{
		xed_state_t state;
		if ( is_long ) state = { XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b };
		else           state = { XED_MACHINE_MODE_LONG_COMPAT_32, XED_ADDRESS_WIDTH_32b };

		encoder_request enc_req;
		xed_encoder_instruction_t inst;

		static constexpr std::array<size_t, 4> steps[ 2 ] = {
			{ 32, 16, 8, 0 },
			{ 64, 32, 16, 8 }
		};
		for ( auto size : steps[ is_long ] )
		{
			if ( !size ) break;
			xed_inst( &inst, state, opcode, size, num_ops, ops );
			xed_encoder_request_zero_set_mode( &enc_req, &state );
			if ( xed_convert_to_encoder_request( &enc_req, &inst ) )
				return enc_req;
		}
		return status{ XED_ERROR_GENERAL_ERROR };
	}
	template <typename T = std::initializer_list<decoded_instruction>> requires xstd::TypedIterable<decoded_instruction, T>
	inline static result<std::vector<uint8_t>> encode_n( const T& container )
	{
		result<std::vector<uint8_t>> res;
		auto& buf = res.result.emplace();
		for ( encoder_request ins : container )
		{
			auto enc = ins.encode();
			if ( !enc ) return enc.status;
			buf.insert( buf.end(), enc->begin(), enc->end() );
		}
		return res;
	}
	inline static result<std::vector<uint8_t>> make_nop( size_t len )
	{
		result<std::vector<uint8_t>> res; 
		auto& buf = res.result.emplace();
		buf.resize( len );
		res.status = xed_encode_nop( buf.data(), len );
		return res;
	}

	// Simpler wrappers.
	//
	inline static result<decoded_instruction> decode32( const void* data, size_t length = max_ins_len ) { return decode( data, false, length ); }
	inline static result<decoded_instruction> decode64( const void* data, size_t length = max_ins_len ) { return decode( data, true, length ); }
	template <typename T = std::initializer_list<uint8_t>> requires ( xstd::TypedIterable<uint8_t, T> && xstd::is_contiguous_iterable_v<T> )
	inline static result<decoded_instruction> decode32( T&& container ) { return decode( &*std::begin( container ), false, std::size( container ) ); }
	template <typename T = std::initializer_list<uint8_t>> requires ( xstd::TypedIterable<uint8_t, T> && xstd::is_contiguous_iterable_v<T> )
	inline static result<decoded_instruction> decode64( T&& container ) { return decode( &*std::begin( container ), true,  std::size( container ) ); }

	inline static std::vector<decoded_instruction> decode32_n( const void* data, size_t length ) { return decode_n( data, false, length ); }
	inline static std::vector<decoded_instruction> decode64_n( const void* data, size_t length ) { return decode_n( data, true, length ); }
	template <typename T = std::initializer_list<uint8_t>> requires ( xstd::TypedIterable<uint8_t, T> && xstd::is_contiguous_iterable_v<T> )
	inline static std::vector<decoded_instruction> decode32_n( T&& container ) { return decode_n( &*std::begin( container ), false, std::size( container ) ); }
	template <typename T = std::initializer_list<uint8_t>> requires ( xstd::TypedIterable<uint8_t, T> && xstd::is_contiguous_iterable_v<T> )
	inline static std::vector<decoded_instruction> decode64_n( T&& container ) { return decode_n( &*std::begin( container ), true,  std::size( container ) ); }
	
	template <typename T = std::initializer_list<xed_encoder_operand_t>> requires ( xstd::TypedIterable<xed_encoder_operand_t, T> && xstd::is_contiguous_iterable_v<T> )
	inline static result<encoder_request> encode32( xed_iclass_enum_t opcode, const T& container ) { return encode( opcode, false, &*std::begin( container ), std::size( container ) ); }
	template <typename T = std::initializer_list<xed_encoder_operand_t>> requires ( xstd::TypedIterable<xed_encoder_operand_t, T> && xstd::is_contiguous_iterable_v<T> )
	inline static result<encoder_request> encode64( xed_iclass_enum_t opcode, const T& container ) { return encode( opcode, true, &*std::begin( container ), std::size( container ) ); }
	
	template <typename... Tx>
	inline static result<encoder_request> encode32i( xed_iclass_enum_t opcode, Tx&&... operand ) { return encode32( opcode, std::initializer_list<xed_encoder_operand_t>{ std::forward<Tx>( operand )... } ); }
	template <typename... Tx>
	inline static result<encoder_request> encode64i( xed_iclass_enum_t opcode, Tx&&... operand ) { return encode64( opcode, std::initializer_list<xed_encoder_operand_t>{ std::forward<Tx>( operand )... } ); }


	// Imm0 wrapper choosing the smallest size.
	//
	template<xstd::Integral T>
	inline static xed_encoder_operand_t imm0( T value, bool allow_16 = false )
	{
		auto svalue = ( std::make_signed_t<T> ) value;
		if ( INT8_MIN <= svalue && svalue <= INT8_MAX )
			return xed_imm0( ( int64_t ) svalue, 8 );
		if ( allow_16 && INT16_MIN <= svalue && svalue <= INT16_MAX )
			return xed_imm0( ( int64_t ) svalue, 16 );
		if ( INT32_MIN <= svalue && svalue <= INT32_MAX )
			return xed_imm0( ( int64_t ) svalue, 32 );
		return xed_imm0( ( int64_t ) svalue, 64 );
	}
};
