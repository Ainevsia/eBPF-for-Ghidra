package ghidra.app.plugin.core.analysis;

import ghidra.app.plugin.core.function.editor.FunctionEditorModel;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.app.util.importer.MessageLog;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.address.*;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.Pointer64DataType;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.UnsignedLongDataType;
import ghidra.program.model.data.UnsignedLongLongDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.Function;

public class eBPFSolanaAnalyzer extends AbstractAnalyzer {

	private final static String PROCESSOR_NAME = "eBPF";
	private final static String NAME = "Solana syscall ID";
	private final static String DESCRIPTION =
			"Searches external symbols for solana syscalls and applies function signatures";
	
	private long lastTransactionId = -1;

	public eBPFSolanaAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().equals(
			Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME));
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		
		// only perform this analysis once per transaction
		long txId = program.getCurrentTransaction().getID();
		if (txId == lastTransactionId) {
			return true;
		}
		lastTransactionId = txId;

		BookmarkManager bmmanager = program.getBookmarkManager();
		bmmanager.removeBookmarks("Error", "Bad Instruction", monitor);
		
		SymbolTable table = program.getSymbolTable();
		boolean includeDynamicSymbols = true;
		SymbolIterator symbols = table.getAllSymbols(includeDynamicSymbols);
		
		// insert known data types into the DB
		CategoryPath solanaCategory = new CategoryPath("/SOLANA");
		CategoryPath rustCategory = new CategoryPath("/RUST");

		TypedefDataType u64Type = new TypedefDataType(rustCategory, "u64", UnsignedLongLongDataType.dataType);
		program.getDataTypeManager().addDataType(u64Type, null);

		TypedefDataType u32Type = new TypedefDataType(rustCategory, "u32", UnsignedLongDataType.dataType);
		program.getDataTypeManager().addDataType(u32Type, null);

		TypedefDataType u8Type = new TypedefDataType(rustCategory, "u8", ByteDataType.dataType);
		program.getDataTypeManager().addDataType(u8Type, null);
		
		
		// rust Vector
		Structure vecStruct = new StructureDataType(rustCategory, "Vec", 0);
		vecStruct.add(new Pointer64DataType(u8Type), "buf", "");
		vecStruct.add(u64Type, "capacity", "");
		vecStruct.add(u64Type, "len", "");
		program.getDataTypeManager().addDataType(vecStruct, null);
		
		// rust u8 slice ([u8])
		Structure u8SliceStruct = new StructureDataType(rustCategory, "u8Slice", 0);
		u8SliceStruct.add(new Pointer64DataType(u8Type), "buf", "");
		u8SliceStruct.add(u64Type, "len", "");
		program.getDataTypeManager().addDataType(u8SliceStruct, null);
		
		// Pubkey
		Structure pubkeyStruct = new StructureDataType(solanaCategory, "Pubkey", 0);
		pubkeyStruct.add(
				new ArrayDataType(new ByteDataType(), 32, 1),
				"data",
				"");
		program.getDataTypeManager().addDataType(pubkeyStruct, null);
		

		// return values of entrypoint::deserialize call
		Structure deserializeRetStruct = new StructureDataType(solanaCategory, "DeserializeRetVals", 0);
		deserializeRetStruct.add(new Pointer64DataType(pubkeyStruct), "program_id", "");
		deserializeRetStruct.add(vecStruct, "accounts", "");
		deserializeRetStruct.add(u8SliceStruct, "instruction_data", "");
		program.getDataTypeManager().addDataType(deserializeRetStruct, null);
		
		// void entrypoint::deserialize(DeserializeRetVals * return_values, u8 *transaction_data)
		FunctionDefinitionDataType deserializeDef = new FunctionDefinitionDataType(
				solanaCategory, "entrypoint::deserialize");
		deserializeDef.setReturnType(VoidDataType.dataType);
		deserializeDef.setArguments(new ParameterDefinition[] {
				new ParameterDefinitionImpl("return_values", new Pointer64DataType(deserializeRetStruct), null),
				new ParameterDefinitionImpl("transaction_data", new Pointer64DataType(u8Type), null),
		});
		program.getDataTypeManager().addDataType(deserializeDef, null);
		
		// void process_instruction(void *ProcessInstructionRetVals, Pubkey *program_id, Vec *accounts, u8 *instruction_data, u64 instruction_data_len)
		// TODO: implement this data type
		// signature might not be 100% correct
		
		// iterate through external symbols and apply function signatures for syscalls
		for (ghidra.program.model.symbol.Symbol s : symbols) {
			if (monitor.isCancelled())
				return false;

			String funcName = s.getName();
			if (s.isExternal() ? (funcName.startsWith("sol_") || funcName.equals("abort")) : funcName.equals("entrypoint")){
				Function func = program.getFunctionManager().getFunctionAt(s.getAddress());
				FunctionEditorModel model = new FunctionEditorModel(null, func);
				
				switch(s.getName()) {

// vvv CODE IS AUTOGENERATED BY syscalls_codegen.py

        case("entrypoint"):
            model.setSignatureFieldText("u64 entrypoint(u8 *transaction_data)");
            try {
                model.parseSignatureFieldText();
            } catch (CancelledException e) {
                return false;
            } catch (ParseException e) {
                log.appendMsg("Failed parsing solana syscall signature. See exception");
                log.appendException(e);
                break;
            }
            model.apply();				
            func.setComment("Receives raw transaction data as argument. Generally the entrypoint! macro takes care of deserializing this data and calls the user-supplied process_instruction on it. Function calls are usually in this order: - entrypoint::deserialize() - instruction_data.as_slice() - process_instruction() Function signatures for deserialize/process_instruction can be found under the SOLANA category in the DataType manager. They need to be applied manually via right click, edit, copy the signature and paste it into function signature.");
            break;
        

        case("abort"):
            model.setSignatureFieldText("u64 abort()");
            try {
                model.parseSignatureFieldText();
            } catch (CancelledException e) {
                return false;
            } catch (ParseException e) {
                log.appendMsg("Failed parsing solana syscall signature. See exception");
                log.appendException(e);
                break;
            }
            model.apply();				
            func.setComment("TODO");
            break;
        

        case("sol_panic_"):
            model.setSignatureFieldText("u64 sol_panic_(char *file, u64 len, u64 line, u64 column)");
            try {
                model.parseSignatureFieldText();
            } catch (CancelledException e) {
                return false;
            } catch (ParseException e) {
                log.appendMsg("Failed parsing solana syscall signature. See exception");
                log.appendException(e);
                break;
            }
            model.apply();				
            func.setComment("TODO");
            break;
        

        case("sol_log_"):
            model.setSignatureFieldText("u64 sol_log_(char *str, u64 len)");
            try {
                model.parseSignatureFieldText();
            } catch (CancelledException e) {
                return false;
            } catch (ParseException e) {
                log.appendMsg("Failed parsing solana syscall signature. See exception");
                log.appendException(e);
                break;
            }
            model.apply();				
            func.setComment("TODO");
            break;
        

        case("sol_log_64_"):
            model.setSignatureFieldText("u64 sol_log_64_(u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5)");
            try {
                model.parseSignatureFieldText();
            } catch (CancelledException e) {
                return false;
            } catch (ParseException e) {
                log.appendMsg("Failed parsing solana syscall signature. See exception");
                log.appendException(e);
                break;
            }
            model.apply();				
            func.setComment("TODO");
            break;
        

        case("sol_log_compute_units_"):
            model.setSignatureFieldText("u64 sol_log_compute_units_()");
            try {
                model.parseSignatureFieldText();
            } catch (CancelledException e) {
                return false;
            } catch (ParseException e) {
                log.appendMsg("Failed parsing solana syscall signature. See exception");
                log.appendException(e);
                break;
            }
            model.apply();				
            func.setComment("TODO");
            break;
        

        case("sol_log_pubkey"):
            model.setSignatureFieldText("u64 sol_log_pubkey(Pubkey *pubkey)");
            try {
                model.parseSignatureFieldText();
            } catch (CancelledException e) {
                return false;
            } catch (ParseException e) {
                log.appendMsg("Failed parsing solana syscall signature. See exception");
                log.appendException(e);
                break;
            }
            model.apply();				
            func.setComment("TODO");
            break;
        

        case("sol_create_program_address"):
            model.setSignatureFieldText("u64 sol_create_program_address(u8 *seeds_addr, u64 seeds_len, Pubkey *program_id, Pubkey *address_out)");
            try {
                model.parseSignatureFieldText();
            } catch (CancelledException e) {
                return false;
            } catch (ParseException e) {
                log.appendMsg("Failed parsing solana syscall signature. See exception");
                log.appendException(e);
                break;
            }
            model.apply();				
            func.setComment("TODO");
            break;
        

        case("sol_try_find_program_address"):
            model.setSignatureFieldText("u64 sol_try_find_program_address(u8 *seeds_addr, u64 seeds_len, Pubkey *program_id, Pubkey *address_out, u8 *bump_seed_out)");
            try {
                model.parseSignatureFieldText();
            } catch (CancelledException e) {
                return false;
            } catch (ParseException e) {
                log.appendMsg("Failed parsing solana syscall signature. See exception");
                log.appendException(e);
                break;
            }
            model.apply();				
            func.setComment("TODO");
            break;
        

        case("sol_sha256"):
            model.setSignatureFieldText("u64 sol_sha256(u8 *data, u64 data_len, u8[32] hash_out)");
            try {
                model.parseSignatureFieldText();
            } catch (CancelledException e) {
                return false;
            } catch (ParseException e) {
                log.appendMsg("Failed parsing solana syscall signature. See exception");
                log.appendException(e);
                break;
            }
            model.apply();				
            func.setComment("TODO");
            break;
        

        case("sol_keccak256"):
            model.setSignatureFieldText("u64 sol_keccak256(u8 *data, u64 data_len, u8[32] hash_out)");
            try {
                model.parseSignatureFieldText();
            } catch (CancelledException e) {
                return false;
            } catch (ParseException e) {
                log.appendMsg("Failed parsing solana syscall signature. See exception");
                log.appendException(e);
                break;
            }
            model.apply();				
            func.setComment("TODO");
            break;
        

        case("sol_secp256k1_recover"):
            model.setSignatureFieldText("u64 sol_secp256k1_recover(u8[32] hash_data, u8 recovery_id, u8[64] signature, u8[64] pubkey_out)");
            try {
                model.parseSignatureFieldText();
            } catch (CancelledException e) {
                return false;
            } catch (ParseException e) {
                log.appendMsg("Failed parsing solana syscall signature. See exception");
                log.appendException(e);
                break;
            }
            model.apply();				
            func.setComment("TODO");
            break;
        

        case("sol_blake3"):
            model.setSignatureFieldText("u64 sol_blake3(u8 *data, u64 data_len, u8[32] hash_out)");
            try {
                model.parseSignatureFieldText();
            } catch (CancelledException e) {
                return false;
            } catch (ParseException e) {
                log.appendMsg("Failed parsing solana syscall signature. See exception");
                log.appendException(e);
                break;
            }
            model.apply();				
            func.setComment("TODO");
            break;
        

        case("sol_zk_token_elgamal_op"):
            model.setSignatureFieldText("u64 sol_zk_token_elgamal_op(u64 operation, u8[64] ciphertext0, u8[64] cipertext1, u8[64] ciphertext_out)");
            try {
                model.parseSignatureFieldText();
            } catch (CancelledException e) {
                return false;
            } catch (ParseException e) {
                log.appendMsg("Failed parsing solana syscall signature. See exception");
                log.appendException(e);
                break;
            }
            model.apply();				
            func.setComment("TODO");
            break;
        

        case("sol_zk_token_elgamal_op_with_lo_hi"):
            model.setSignatureFieldText("u64 sol_zk_token_elgamal_op_with_lo_hi(u64 operation, u8[64] ciphertext0, u8[64] ciphertext1_lo, u8[64] ciphertext1_hi, u8[64] ciphertext_out)");
            try {
                model.parseSignatureFieldText();
            } catch (CancelledException e) {
                return false;
            } catch (ParseException e) {
                log.appendMsg("Failed parsing solana syscall signature. See exception");
                log.appendException(e);
                break;
            }
            model.apply();				
            func.setComment("TODO");
            break;
        

        case("sol_zk_token_elgamal_op_with_scalar"):
            model.setSignatureFieldText("u64 sol_zk_token_elgamal_op_with_scalar(u64 operation, u8[64] ciphertext, u64 scalar, u8[64] ciphertext_out)");
            try {
                model.parseSignatureFieldText();
            } catch (CancelledException e) {
                return false;
            } catch (ParseException e) {
                log.appendMsg("Failed parsing solana syscall signature. See exception");
                log.appendException(e);
                break;
            }
            model.apply();				
            func.setComment("TODO");
            break;
        

        case("sol_get_clock_sysvar"):
            model.setSignatureFieldText("u64 sol_get_clock_sysvar(void *clock_out)");
            try {
                model.parseSignatureFieldText();
            } catch (CancelledException e) {
                return false;
            } catch (ParseException e) {
                log.appendMsg("Failed parsing solana syscall signature. See exception");
                log.appendException(e);
                break;
            }
            model.apply();				
            func.setComment("TODO");
            break;
        

        case("sol_get_epoch_schedule_sysvar"):
            model.setSignatureFieldText("u64 sol_get_epoch_schedule_sysvar(void *epoch_schedule_out)");
            try {
                model.parseSignatureFieldText();
            } catch (CancelledException e) {
                return false;
            } catch (ParseException e) {
                log.appendMsg("Failed parsing solana syscall signature. See exception");
                log.appendException(e);
                break;
            }
            model.apply();				
            func.setComment("TODO");
            break;
        

        case("sol_get_fees_sysvar"):
            model.setSignatureFieldText("u64 sol_get_fees_sysvar(void *fees_out)");
            try {
                model.parseSignatureFieldText();
            } catch (CancelledException e) {
                return false;
            } catch (ParseException e) {
                log.appendMsg("Failed parsing solana syscall signature. See exception");
                log.appendException(e);
                break;
            }
            model.apply();				
            func.setComment("TODO");
            break;
        

        case("sol_get_rent_sysvar"):
            model.setSignatureFieldText("u64 sol_get_rent_sysvar(void *rent_out)");
            try {
                model.parseSignatureFieldText();
            } catch (CancelledException e) {
                return false;
            } catch (ParseException e) {
                log.appendMsg("Failed parsing solana syscall signature. See exception");
                log.appendException(e);
                break;
            }
            model.apply();				
            func.setComment("TODO");
            break;
        

        case("sol_memcpy_"):
            model.setSignatureFieldText("u64 sol_memcpy_(u8 *dst, u8 *src, u64 len)");
            try {
                model.parseSignatureFieldText();
            } catch (CancelledException e) {
                return false;
            } catch (ParseException e) {
                log.appendMsg("Failed parsing solana syscall signature. See exception");
                log.appendException(e);
                break;
            }
            model.apply();				
            func.setComment("TODO");
            break;
        

        case("sol_memmove_"):
            model.setSignatureFieldText("u64 sol_memmove_(u8 *dst, u8 *src, u64 len)");
            try {
                model.parseSignatureFieldText();
            } catch (CancelledException e) {
                return false;
            } catch (ParseException e) {
                log.appendMsg("Failed parsing solana syscall signature. See exception");
                log.appendException(e);
                break;
            }
            model.apply();				
            func.setComment("TODO");
            break;
        

        case("sol_memcmp_"):
            model.setSignatureFieldText("u64 sol_memcmp_(u8 *s1, u8 *s2, u64 len)");
            try {
                model.parseSignatureFieldText();
            } catch (CancelledException e) {
                return false;
            } catch (ParseException e) {
                log.appendMsg("Failed parsing solana syscall signature. See exception");
                log.appendException(e);
                break;
            }
            model.apply();				
            func.setComment("TODO");
            break;
        

        case("sol_memset_"):
            model.setSignatureFieldText("u64 sol_memset_(u8 *dst, u8 val, u64 len)");
            try {
                model.parseSignatureFieldText();
            } catch (CancelledException e) {
                return false;
            } catch (ParseException e) {
                log.appendMsg("Failed parsing solana syscall signature. See exception");
                log.appendException(e);
                break;
            }
            model.apply();				
            func.setComment("TODO");
            break;
        

        case("sol_invoke_signed_c"):
            model.setSignatureFieldText("u64 sol_invoke_signed_c(void *instruction, void *account_infos, u64 account_infos_len, void *signer_seeds, u64 signer_seeds_len)");
            try {
                model.parseSignatureFieldText();
            } catch (CancelledException e) {
                return false;
            } catch (ParseException e) {
                log.appendMsg("Failed parsing solana syscall signature. See exception");
                log.appendException(e);
                break;
            }
            model.apply();				
            func.setComment("TODO: better types");
            break;
        

        case("sol_invoke_signed_rust"):
            model.setSignatureFieldText("u64 sol_invoke_signed_rust(void *instruction, void *account_infos, u64 account_infos_len, void *signer_seeds, u64 signer_seeds_len)");
            try {
                model.parseSignatureFieldText();
            } catch (CancelledException e) {
                return false;
            } catch (ParseException e) {
                log.appendMsg("Failed parsing solana syscall signature. See exception");
                log.appendException(e);
                break;
            }
            model.apply();				
            func.setComment("TODO: better types");
            break;
        

        case("sol_alloc_free_"):
            model.setSignatureFieldText("void *sol_alloc_free_(u64 size, void *free_addr)");
            try {
                model.parseSignatureFieldText();
            } catch (CancelledException e) {
                return false;
            } catch (ParseException e) {
                log.appendMsg("Failed parsing solana syscall signature. See exception");
                log.appendException(e);
                break;
            }
            model.apply();				
            func.setComment("free_addr=0 will allocate and return the allocated pointer otherwise free_addr must be a pointer previously returned by this function");
            break;
        

        case("sol_set_return_data"):
            model.setSignatureFieldText("u64 sol_set_return_data(u8 *data, u64 len)");
            try {
                model.parseSignatureFieldText();
            } catch (CancelledException e) {
                return false;
            } catch (ParseException e) {
                log.appendMsg("Failed parsing solana syscall signature. See exception");
                log.appendException(e);
                break;
            }
            model.apply();				
            func.setComment("TODO");
            break;
        

        case("sol_get_return_data"):
            model.setSignatureFieldText("u64 sol_get_return_data(u8 *data_out, u64 len, Pubkey *program_id)");
            try {
                model.parseSignatureFieldText();
            } catch (CancelledException e) {
                return false;
            } catch (ParseException e) {
                log.appendMsg("Failed parsing solana syscall signature. See exception");
                log.appendException(e);
                break;
            }
            model.apply();				
            func.setComment("TODO");
            break;
        

        case("sol_log_data"):
            model.setSignatureFieldText("u64 sol_log_data(u8 **data, u64 len)");
            try {
                model.parseSignatureFieldText();
            } catch (CancelledException e) {
                return false;
            } catch (ParseException e) {
                log.appendMsg("Failed parsing solana syscall signature. See exception");
                log.appendException(e);
                break;
            }
            model.apply();				
            func.setComment("TODO");
            break;
        

        case("sol_get_processed_sibling_instruction"):
            model.setSignatureFieldText("u64 sol_get_processed_sibling_instruction(u64 index, void *meta, Pubkey *program_id, u8 *data, void *accounts)");
            try {
                model.parseSignatureFieldText();
            } catch (CancelledException e) {
                return false;
            } catch (ParseException e) {
                log.appendMsg("Failed parsing solana syscall signature. See exception");
                log.appendException(e);
                break;
            }
            model.apply();				
            func.setComment("TODO");
            break;
        

        case("sol_get_stack_height"):
            model.setSignatureFieldText("u64 sol_get_stack_height()");
            try {
                model.parseSignatureFieldText();
            } catch (CancelledException e) {
                return false;
            } catch (ParseException e) {
                log.appendMsg("Failed parsing solana syscall signature. See exception");
                log.appendException(e);
                break;
            }
            model.apply();				
            func.setComment("TODO");
            break;
        
// ^^^ CODE IS AUTOGENERATED BY syscalls_codegen.py

						
					default:
						log.appendMsg("Warning: Found external function beginning with sol_ but no known name: " + s.getName());
						break;
				}
				
				// assign calling convention after the signature update since it gets overwritten otherwise
				try {
					func.setCallingConvention("ebpf_call");
				} catch (InvalidInputException e) {
					e.printStackTrace();
				}
				bmmanager.setBookmark(s.getAddress(), "Analysis", "eBPF-helpers", "eBPF-helper Identified");
			}			
		}
		
		return true;
	}
}
