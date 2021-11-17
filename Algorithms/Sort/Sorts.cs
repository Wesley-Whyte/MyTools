using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Algorithms.Sort
{
    public static class Sorts
    {
        public static void bubbleDown<T>(this T collection)
        where T : IList<T>
        {
            foreach (var item in collection)
            {
                foreach (var  in collection)
                {

                }
            }
        }

        private static void Swap<T>(this T collection, int i, int j)
        where T : IList<T>
        {
            T hold = collection[i];
            collection[i] = collection[j];
            collection[j] = hold;
        }
    }
}
