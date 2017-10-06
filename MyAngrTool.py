import angr
import cle
import sys

class MyAngrTool:	
	def __init__(self, binary1, binary2, option):
		self._bin1 = binary1
		self._bin2 = binary2
		self._proj = angr.Project(self._bin1, load_options={'auto_load_libs':False})
		self._cfg = self._proj.analyses.CFG()
		self._option = option
		self._choices = {
			'cle': self.get_cle_out,
			'cfg': self.get_cfg_out,
			'bindiff': self.get_bindiff_out,
		}
	
	def main(self):
		if(option == 'cle'):
			self._choices[option]('cle_result.out')
		elif(option == 'cfg'):
			self._choices[option]('cfg_result.out')
		elif(option == 'bindiff'):
			self._choices[option]('bindiff_result.out')
		else:
			print '--------------------------------------------------------'
			print '@author	:	Ashwin Joshi, Ashwin.Joshi2@utdallas.edu.'
			print '--------------------------------------------------------'
			print 'Usage:'
			print 'python MyAngrTool.py [option] ... [cle cle_analysis | cfg cfg_analysis | bindiff bindiff_analysis] [target_bin]...[target_bin]'
			print 'Options and their usage:'
			print 'cle		:	Get CLE Analysis of target binary.'
			print '				Usage	:	ipython MyAngrTool.py cle bin'
			print 'cfg		:	Get CFG Analysis of target binary.'
			print '				Usage	:	ipython MyAngrTool.py cfg bin'
			print 'bindiff	:	Get BinDiff Analysis of target binary.'
			print '				Usage	:	ipython MyAngrTool bindiff bin1 bin2'
			print '--------------------------------------------------------'
			print 'Output will be generated as:'
			print 'cle_result.out		: Output of CLE Analysis.'
			print 'cfg_result.out		: Output of CFG Analysis.'
			print 'bindiff_result.out	: Output of BinDiff Analysis.'
			print '--------------------------------------------------------'
	
	
	def get_cle_out(self, file_name):
		with open(file_name, 'w') as f:
			f.write('# CLE Analysis for binary :'+self.getBinName()+'\n')
			f.write('#START'+'\n')
			f.write('#--------------------------------------'+'\n')
			f.write('#Task-1: Entry Address in hex form.'+'\n')
			f.write(self.getEntryPoint()+'\n')
			f.write('#Task-2: Min & Max addresses of binary memory content.'+'\n')
			f.write('Min addr.:'+self.getMinAddr()+'\n')
			f.write('Max addr.:'+self.getMaxAddr()+'\n')
			f.write('#Task-3: Full name of binary.'+'\n')
			f.write(self.getBinName()+'\n')
			f.write('#Task-4: Shared objects of binary.'+'\n')
			f.write(str(self.getSharedObjects())+'\n')
			f.write('#Task-5: GOT Entry address for printf function.'+'\n')
			f.write(self.getGOT_addr_func('printf')+'\n')
			f.write('#--------------------------------------'+'\n')
			f.write('#END'+'\n')
			f.close()
			
			
	def get_cfg_out(self, file_name):
		with open(file_name, 'w') as f:
			f.write('# CFG Analysis for binary :'+self.getBinName()+'\n')
			f.write('#START'+'\n')
			f.write('#--------------------------------------'+'\n')
			f.write('#Task-1: Number of nodes & edges in CFG of target binary.'+'\n')
			(n,e) = self.get_bin_CFG()
			f.write('No. of nodes:'+str(n)+'\n')
			f.write('No. of edges:'+str(e)+'\n')
			f.write('#Task-2: Entry address of binary.'+'\n')
			f.write(self.getEntryPoint()+'\n')
			f.write('#Task-3: Name of entry function.'+'\n')
			f.write(str(self.get_bin_entry_func_name())+'\n')
			f.write('#Task-4: Starting address for main function.'+'\n')
			f.write(str(self.get_bin_func_entry_addr('main'))+'\n')
			f.write('#Task-5: Addresses of basic blocks resulting in calls to other functions inside main function.'+'\n')
			f.write(str(self.get_bin_bblAddr_func('main'))+'\n')
			f.write('#--------------------------------------'+'\n')
			f.write('#END'+'\n')
			f.close()		
	
	
	
	def get_bindiff_out(self, file_name):
		(id_addr,diff_addr,un_addr) = self.get_BinDiff(self._bin1, self._bin2)
		
		with open(file_name, 'w') as f:
			f.write('# BinDiff Analysis\n')
			f.write('#START'+'\n')
			f.write('#--------------------------------------'+'\n')
			f.write('#Addresses of identical functions.'+'\n')
			
			if id_addr:
				id_addr = [(hex(a),hex(b)) for (a,b) in id_addr]
				f.write('\n'.join('[%s,%s]' % x for x in id_addr))
				f.write('\n')
			else:
				f.write(str(id_addr)+'\n')
			
			f.write('#Addresses of differing functions.'+'\n')
			
			if diff_addr:
				diff_addr = [(hex(a),hex(b)) for (a,b) in diff_addr]
				f.write('\n'.join('[%s,%s]' % x for x in diff_addr))
				f.write('\n')
			else:
				f.write(str(diff_addr)+'\n')
				
			f.write('#Addresses of unmatched functions.'+'\n')
			f.write(str(un_addr)+'\n')
			f.write('#--------------------------------------'+'\n')
			f.write('#END'+'\n')
			f.close()		
	
	#----------------Lab task 1: CLE related tasks ------------------
	
	"""
	Get the entry point address of the target binary.
	Returns: HEX format address.
	"""
	def getEntryPoint(self):
		return hex(self._proj.entry)
	
	"""
	Returns: HEX format min address in the target binary. 
	"""
	def getMinAddr(self):
		return hex(self._proj.loader.min_addr)
	
	"""
	Returns: HEX format max address in the target binary.
	"""
	def getMaxAddr(self):
		return hex(self._proj.loader.max_addr)
	
	"""
	Returns: The full name of the target binary.
	"""
	def getBinName(self):
		return self._proj.filename
	
	"""
	Returns: Shared objects of the target binary.
	"""
	def getSharedObjects(self):
		return self._proj.loader.shared_objects
		
	"""
	Returns: Get GOT address of some function
	specified by its name
	Example: printf, puts, gets, etc.
	"""
	def getGOT_addr_func(self, func_name):
		main_obj = self._proj.loader.main_object
		func_GOT_obj = main_obj.imports[func_name]
		return hex(func_GOT_obj.rebased_addr)
	
	# -----------END of Lab Task 1----------------------------------------
	
	# -----------Lab Task 2: CFG analysis of target binary ---------------
	"""
	Returns: # no of nodes and edges in the 
	CFG of the target binary.
	"""
	def get_bin_CFG(self):
		bin_cfg_nodes = self._cfg.graph.nodes()
		bin_cfg_edges = self._cfg.graph.edges()
		
		return len(bin_cfg_nodes), len(bin_cfg_edges)
		
	"""
	Returns: Name of the entry function of the binary.
	"""
	def get_bin_entry_func_name(self):
		entry_func = self._cfg.kb.functions[self._proj.entry]
		return entry_func.name

	"""
	Returns: Entry address of a function in target binary
	given the function name.
	"""
	def get_bin_func_entry_addr(self, func_name):
		return self._cfg.kb.functions[func_name]
		
	"""
	Returns: A list of all the addresses of basic blocks 
	which end in calls out to other functions inside some 
	function specified by its name.
	"""
	def get_bin_bblAddr_func(self, func_name):
		func_point = self._cfg.kb.functions[func_name]
		return map(hex, func_point.get_call_sites())
	
	# -----Lab Task 3: BinDiff Analysis -------------------------------------
	
	def get_BinDiff(self, bin1, bin2):
		b1 = angr.Project(bin1, load_options={'auto_load_libs':False})
		b2 = angr.Project(bin2, load_options={'auto_load_libs':False})
		bindiff = b1.analyses.BinDiff(b2)
		identical_func_addr = bindiff.identical_functions
		differing_func_addr = bindiff.differing_functions
		unmatched_func_addr = bindiff.unmatched_functions
		return identical_func_addr, differing_func_addr, unmatched_func_addr
	
	
	# ----End of Lab Task 3 ---------------------------------------------------
if __name__ == '__main__':
	
	if(len(sys.argv) == 3):
		option = sys.argv[1]
		target_bin = sys.argv[2]
		MyAngrTool(target_bin, None ,option).main()
	elif(len(sys.argv) == 4):
		option = sys.argv[1]
		bin1 = sys.argv[2]
		bin2 = sys.argv[3]
		MyAngrTool(bin1,bin2,option).main()
	else:
		print '--------------------------------------------------------'
		print '@author	:	Ashwin Joshi, Ashwin.Joshi2@utdallas.edu.'
		print '--------------------------------------------------------'
		print 'Usage:'
		print 'python MyAngrTool.py [option] ... [cle cle_analysis | cfg cfg_analysis | bindiff bindiff_analysis] [target_bin]...[target_bin]'
		print 'Options and their usage:'
		print 'cle		:	Get CLE Analysis of target binary.'
		print '				Usage	:	ipython MyAngrTool.py cle bin'
		print 'cfg		:	Get CFG Analysis of target binary.'
		print '				Usage	:	ipython MyAngrTool.py cfg bin'
		print 'bindiff	:	Get BinDiff Analysis of target binary.'
		print '				Usage	:	ipython MyAngrTool bindiff bin1 bin2'
		print '--------------------------------------------------------'
		print 'Output will be generated as:'
		print 'cle_result.out		: Output of CLE Analysis.'
		print 'cfg_result.out		: Output of CFG Analysis.'
		print 'bindiff_result.out	: Output of BinDiff Analysis.'
		print '--------------------------------------------------------'
	
	
	
