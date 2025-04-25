Expectativas de respostas:
Classe Tarefa:
public class Tarefa
{
public string Descricao { get; set; }
public bool Concluida { get; set; }
public Tarefa(string descricao)
{
Descricao = descricao;
Concluida = false;
}
public void MarcarComoConcluida()
{
Concluida = true;
}
public override string ToString()
{
return $"{Descricao} - {(Concluida ? "Concluída" : "Pendente")}";
}
}
Slide 6
Gerenciamento de tarefas no Program.cs:
using System;
using System.Collections.Generic;
class Program
{
static void Main(string[] args)
{
List<Tarefa> tarefas = new List<Tarefa>();
int opcao;
do
{
Console.WriteLine("1. Adicionar Tarefa");
Console.WriteLine("2. Listar Tarefas");
Console.WriteLine("3. Sair");
Console.Write("Escolha uma opção: ");
opcao = int.Parse(Console.ReadLine());
Slide 6
switch (opcao)
{
case 1:
Console.Write("Digite a descrição da tarefa: ");
string descricao = Console.ReadLine();
tarefas.Add(new Tarefa(descricao));
break;
case 2:
Console.WriteLine("Lista de Tarefas:");
foreach (var tarefa in tarefas)
{
Console.WriteLine(tarefa);
}
break;
case 3:
Console.WriteLine("Saindo...");
break;
default:
Console.WriteLine("Opção inválida!");
break;
}
} while (opcao != 3);
}
}
