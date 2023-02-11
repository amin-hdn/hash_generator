import hashlib
import tkinter as tk
from tkinter import ttk

class Root(tk.Tk):
    # hash_str_1 = ''
    # hash_str_2 = ''
    def __init__(self) :
        super().__init__()
        # wondows paramaters
        self.title("Hash Generator")
        self.geometry("600x400")
        self.resizable(1, 1)
        # variables that i will need
        self.hashed_str_1 = tk.StringVar(self)
        self.hashed_str_2 = tk.StringVar(self)
        self.message = tk.StringVar(self)
        self.selected_hash =tk.StringVar(self, value='md5')

        # all Entries
        self.input_field_1 = tk.Entry(
                                    self,
                                    textvariable=self.message,
                                    justify="left" , 
                                      bd='3px')
        self.input_field_2 = tk.Entry(
                                    self, 
                                    justify="left", 
                                    bd='3px'  )
        # all Button
        self.hash_button_1 = tk.Button(self,
                                       text="Hash",
                                       command=lambda:self.hash_string(val=1),
                                       activebackground='#959595',
                                       width=17)
        self.hash_button_2 = tk.Button(self,
                                     text="Hash",
                                      command=lambda:self.hash_string(val=2),
                                      activebackground='#959595',
                                      width=17)
        self.valide_button= tk.Button(self,
                                    text="valider",
                                    command=self.compare_hash,activebackground='#959595',
                                    width=17 )
        self.copy_button = tk.Button(
                	                self,text='copier', 
                	                command=self.copy_the_message,
                	                activebackground='#959595',
                	                width=17)
        self.exit_button = tk.Button(
                                    self,
                                    text='exit', 
                                    command=lambda:self.destroy())
        # all Combobox
        self.hash = ttk.Combobox(self, textvariable=self.selected_hash, values=('md5','sha1','sha224','sha256','sha384', 'sha512') , state='readonly', justify='center' )

        # all labels
        self.result_label_1 = tk.Label(self, text="result of hash 1", justify='left',bg='#FFFFFF' , width=17  ,underline=17 , wraplength=100 )
        self.result_label_2 = tk.Label(self, text="result of hash 2", justify='left',bg='#FFFFFF' , width=17  ,underline=17 , wraplength=100 )
        self.validation = tk.Label(self, text="???", justify='center',bg='#FFFFFF', width=20  )
        
        # grid positions
        self.columnconfigure(0,weight=2)
        self.rowconfigure(0,weight=2)
        self.columnconfigure(1,weight=2)
        self.rowconfigure(1,weight=1)
        self.columnconfigure(2,weight=2)
        self.rowconfigure(2,weight=3)
        self.columnconfigure(3,weight=2)
        self.rowconfigure(3,weight=1)

        self.input_field_1.grid(column=0,row=0, sticky=tk.W, padx=0, pady=1)
        self.hash_button_1.grid(column=0,row=1, sticky=tk.W, padx=0, pady=1)
        self.result_label_1.grid(column=0,row=2, sticky=tk.W, padx=0, pady=1)
        
        self.hash.grid(column=1,row=0, sticky=tk.W, padx=0, pady=1)
        self.validation.grid(column=1,row=1, sticky=tk.W, padx=0, pady=1)
        self.copy_button.grid(column=1,row=3, sticky=tk.W, padx=0, pady=1)

        self.input_field_2.grid(column=2,row=0, sticky=tk.W, padx=0, pady=1)
        self.hash_button_2.grid(column=2,row=1, sticky=tk.W, padx=0, pady=1)
        self.result_label_2.grid(column=2,row=2, sticky=tk.W, padx=0, pady=1)

        self.valide_button.grid(column=3,row=1, sticky=tk.W, padx=0, pady=1)
        self.exit_button.grid(column=3,row=3, sticky=tk.W, padx=0, pady=1)
        
    
    def hash_string(self,val):
        hash_fonction= getattr(hashlib,self.selected_hash.get() )
        if val == 1 :
            self.hashed_str_1.set(hash_fonction(self.input_field_1.get().encode()).hexdigest())
            self.result_label_1.config(text=self.hashed_str_1.get())
        if val == 2 :
            self.hashed_str_2.set(hash_fonction(self.input_field_2.get().encode()).hexdigest())
            self.result_label_2.config(text=self.hashed_str_2.get())


    def compare_hash(self):
        if self.hashed_str_1.get() == self.hashed_str_2.get() : 
            self.validation.config(text="validé", fg='#32cd32')
        else : self.validation.config(text="non validé",fg='#ff0000')
    
    def copy_the_message(self):
        self.input_field_2.delete(0,len(self.input_field_2.get()) )
        self.input_field_2.insert(0,self.message.get())
    


        
if __name__ == "__main__":
    
    root = Root()
    root.mainloop()
