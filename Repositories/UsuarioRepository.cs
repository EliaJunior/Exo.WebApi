using Exo.WebApi.Contexts;
using Exo.WebApi.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Exo.WebApi.Repositories 
{
    public class UsuarioRepository
    {
        private readonly ExoContext _context;
        public UsuarioRepository(ExoContext context){
            _context = context;
        }

        public List<Usuario> Listar(){
            return _context.Usuarios.ToList();
        }

        public void Cadastrar(Usuario usuario){
            _context.Usuarios.Add(usuario);
            _context.SaveChanges();
        }

        public Usuario BuscarporId(int id){
            return _context.Usuarios.Find(id);
        }

        public void Atualizar(int id, Usuario usuario)
        {
            Usuario usuarioBuscado = _context.Usuarios.Find(id);
            if (usuarioBuscado !=null){
                usuarioBuscado.Email = usuario.Email;
                usuarioBuscado.Senha = usuario.Senha;
            }
            _context.Usuarios.Update(usuarioBuscado);
            _context.SaveChanges();
        }

        public void Deletar(int id)
        {
            Usuario usuarioBuscado = _context.Usuarios.Find(id);
            _context.Usuarios.Remove(usuarioBuscado);
            _context.SaveChanges();
        }
    }
}